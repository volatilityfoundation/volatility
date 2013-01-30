# Volatility
# Copyright (C) 2010 Brendan Dolan-Gavitt
# Copyright (c) 2011 Michael Cohen <scudette@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import re,copy
import sys, os
import zipfile
import struct

import volatility.plugins
from volatility import cache
from volatility import debug
from volatility import obj
from volatility.plugins.overlays import basic
import volatility.addrspace as addrspace

class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def generate_suggestions(self):

        profile = self.obj_vm.profile

        if self.obj_vm.profile.metadata.get('memory_model', '32bit') == "32bit":
            ret = profile.get_symbol("_IdlePDPT")
            # on 10.5.x the PDTD symbol is a pointer instead of an array like 10.6 and 10.7
            if ret % 0x1000:
                ret = self.obj_vm.read(ret, 4)
                ret = struct.unpack("<I", ret)[0]
        else:
            ret = profile.get_symbol("_IdlePML4")
            # so it seems some kernels don't define this as the physical address, but actually the virtual
            # while others define it as the physical, easy enough to figure out on the fly
            if ret > 0xffffff8000000000:
                ret = ret - 0xffffff8000000000

        yield ret

# the intel check, simply checks for the static paging of init_task
class VolatilityMacIntelValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid Mac Intel Paged space"""

    def generate_suggestions(self):
        version_addr = self.obj_vm.profile.get_symbol("_version")

        string = self.obj_vm.read(version_addr, 6)

        if string == "Darwin":
            yield True
        else:
            yield False
        
class proc(obj.CType):   
    @property
    def p_gid(self):
        cred = self.p_ucred

        if hasattr(cred, "cr_posix"):
            ret = cred.cr_posix.cr_groups[0]
        else:
            ret = cred.cr_groups[0]     
    
        return ret

    @property
    def p_uid(self):
        cred = self.p_ucred

        if hasattr(cred, "cr_posix"):
            ret = cred.cr_posix.cr_uid
        else:
            ret = cred.cr_uid     
        
        return ret
    
    def get_process_address_space(self):
        task = obj.Object("task", offset = self.task, vm = self.obj_vm)  
        cr3 = task.map.pmap.pm_cr3
        try:
            proc_as = self.obj_vm.__class__(self.obj_vm.base, self.obj_vm.get_config(), dtb = cr3)
        except addrspace.ASAssertionError, e:
            print "Error: %s" % str(e)
            debug.error("This plugin does not work when analyzing a sample from a 64bit computer running a 32bit kernel.")

        return proc_as 

def exec_vtypes(filename):
    env = {}
    exec(filename, dict(__builtins__ = None), env)
    return env["mac_types"]

def parse_dsymutil(data, module):
    """Parse the symbol file."""
    sys_map = {}
    sys_map[module] = {}

    want_lower = ["_IdlePML4"]        

    arch = ""

    # get the system map
    for line in data.splitlines():
        ents = line.split()

        match = re.search("\[.*?\)\s+[0-9A-Fa-z]+\s+\d+\s+([0-9A-Fa-f]+)\s'(\w+)'", line)

        if match:
            (addr, name) = match.groups()

            addr = int(addr, 16)

            if addr == 0:
                continue

            if not name in sys_map[module]:
                sys_map[module][name] = [(0, "default value")]

            # every symbol is in the symbol table twice
            # except for the entries in 'want_lower', we need the higher address for all 
            if name in sys_map[module]:
                oldaddr = sys_map[module][name][0][0]
    
                if oldaddr > addr and name not in want_lower:
                    pass
                else:
                    sys_map[module][name] = [(addr, "sym type?")]
            else:
                sys_map[module][name] = [(addr, "sym type?")]

        elif line.find("Symbol table for") != -1:
            if line.find("i386") != -1:
                arch = "32bit"
            else:
                arch = "64bit"

    if arch == "":
        return None

    return arch, sys_map

class DWARFParser(object):
    """A parser for DWARF files."""

    # Nasty, but appears to parse the lines we need
    dwarf_header_regex = re.compile(
        r'<(?P<level>\d+)><(?P<statement_id>[0-9+]+)><(?P<kind>\w+)>')
    dwarf_key_val_regex = re.compile(
        '\s*(?P<keyname>\w+)<(?P<val>[^>]*)>')

    sz2tp = {8: 'long long', 8: 'long', 2: 'short', 1: 'char'}
    tp2vol = {
        'bool' : 'int',
        '_Bool': 'unsigned char',
        'char': 'char',
        'float': 'float',
        'double': 'double',
        'long double': 'double',
        'int': 'int',
        'long int': 'long',
        'long long int': 'long long',
        'long long unsigned int': 'unsigned long long',
        'long unsigned int': 'unsigned long',
        'short int': 'short',
        'short unsigned int': 'unsigned short',
        'signed char': 'signed char',
        'unsigned char': 'unsigned char',
        'unsigned int': 'unsigned int',
    }


    def __init__(self):
        self.current_level = -1
        self.name_stack = []
        self.id_to_name = {}
        self.all_vtypes = {}
        self.vtypes = {}
        self.enums = {}
        self.all_vars = {}
        self.vars = {}
        self.all_local_vars = []
        self.local_vars = []
        self.anons = 0

    def resolve(self, memb):
        """Lookup anonymouse member and replace it with a well known one."""
        # Reference to another type
        if isinstance(memb, str) and memb.startswith('<'):
            resolved = self.id_to_name[memb[1:]]

            ret = self.resolve(resolved)

        elif isinstance(memb, list):
            ret = [self.resolve(r) for r in memb]
        else:
            # Literal
            ret = memb

        return ret

    def resolve_refs(self):
        """Replace references with types."""
        for v in self.vtypes:
            for m in self.vtypes[v][1]:
                self.vtypes[v][1][m] = self.resolve(self.vtypes[v][1][m])

        return self.vtypes

    def deep_replace(self, t, search, repl):
        """Recursively replace anonymous references."""
        if t == search:
            return repl

        elif isinstance(t, list):
            return [self.deep_replace(x, search, repl) for x in t]
        else: return t

    def get_deepest(self, t):
        if isinstance(t, list):
            if len(t) == 1:
                return t[0]
            else:
                for part in t:
                    res = self.get_deepest(part)
                    if res:
                        return res

                return None

        return None

    def base_type_name(self, data):
        """Replace references to base types."""
        if 'AT_name' in data:
            return self.tp2vol[data['AT_name']]
        else:
            sz = int(data['AT_byte_size'])
            if data['AT_encoding'] == 'ATE_unsigned':
                return 'unsigned ' + self.sz2tp[sz]
            else:
                return self.sz2tp[sz]

    def feed_line(self, line):

        line = line.replace("\n", "")

        # Does the header match?
        m = self.dwarf_header_regex.match(line)
        if m:
            parsed = m.groupdict()
            parsed['data'] = {}
            # Now parse the key value pairs
            while m:
                i = m.end()
                m = self.dwarf_key_val_regex.search(line, i)
                if m:
                    d = m.groupdict()
                    parsed['data'][d['keyname']] = d['val']
            
            if parsed['kind'] in ('TAG_formal_parameter','TAG_variable'):
                self.process_variable(parsed['data'])
            else:
                self.process_statement(**parsed)

    def process_statement(self, kind, level, data, statement_id):

        if not hasattr(self, "idx"):
            idx = 0

        #print "%s | %s | %s" % (str(kind), str(level), str(data))

        idx = idx + 1

        if idx == 2:
            sys.exit(1)

        """Process a single parsed statement."""
        new_level = int(level)
        if new_level > self.current_level:
            self.current_level = new_level
            self.name_stack.append([])
        elif new_level < self.current_level:
            self.name_stack = self.name_stack[:new_level+1]
            self.current_level = new_level

        self.name_stack[-1] = [kind, statement_id]

        try:
            parent_kind, parent_name = self.name_stack[-2]
        except IndexError:
            parent_kind, parent_name = (None, None)

        if not hasattr(self, "wtf"):
            self.wtf = {}

        self.wtf[kind] = 1

        if kind == 'TAG_compile_unit':
            self.finalize()
            self.vtypes = {}
            self.vars = {}
            self.all_local_vars += self.local_vars
            self.local_vars = []
            self.id_to_name = {}

        elif kind == 'TAG_structure_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'AT_declaration' not in data:
                try:
                    self.vtypes[name] = [ int(data['AT_byte_size']), {} ]
                except:
                    self.vtypes[name] = [ int(data['AT_byte_size'], 16), {} ]

        elif kind == 'TAG_union_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]
            self.vtypes[name] = [ int(data['AT_byte_size']), {} ]

        elif kind == 'TAG_array_type':
            self.name_stack[-1][1] = statement_id
            self.id_to_name[statement_id] = data['AT_type']

        elif kind == 'TAG_enumeration_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'AT_declaration' not in data:
                sz = int(data['AT_byte_size'])
                self.enums[name] = [sz, {}]

        elif kind == 'TAG_pointer_type':
            self.id_to_name[statement_id] = ['pointer', data.get('AT_type', ['void'])]

        elif kind == 'TAG_base_type':
            self.id_to_name[statement_id] = [self.base_type_name(data)]

        elif kind == 'TAG_volatile_type':
            self.id_to_name[statement_id] = data.get('AT_type', ['void'])

        elif kind == 'TAG_const_type':
            self.id_to_name[statement_id] = data.get('AT_type', ['void'])

        elif kind == 'TAG_typedef':
            self.id_to_name[statement_id] = data['AT_type']

        elif kind == 'TAG_subroutine_type':
            self.id_to_name[statement_id] = ['void']         # Don't need these

        elif kind == 'TAG_variable' and level == '1':
            if 'AT_location' in data:
                split = data['AT_location'].split()
                if len(split) > 1:
                    loc = int(split[1], 0)
                    self.vars[data['AT_name']] = [loc, data['AT_type']]

        elif kind == 'TAG_subprogram':
            # IDEK
            pass

        elif kind == 'TAG_member' and parent_kind == 'TAG_structure_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            off = int(data['AT_data_member_location'])

            if 'AT_bit_size' in data and 'AT_bit_offset' in data:
                full_size = int(data['AT_byte_size'])*8
                stbit = int(data['AT_bit_offset'])
                edbit = stbit + int(data['AT_bit_size'])
                stbit = full_size - stbit
                edbit = full_size - edbit
                stbit, edbit = edbit, stbit
                assert stbit < edbit
                memb_tp = ['BitField', dict(start_bit = stbit, end_bit = edbit)]
            else:
                memb_tp = data['AT_type']

            self.vtypes[parent_name][1][name] = [off, memb_tp]

        elif kind == 'TAG_member' and parent_kind == 'TAG_union_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            self.vtypes[parent_name][1][name] = [0, data['AT_type']]

        elif kind == 'TAG_enumerator' and parent_kind == 'TAG_enumeration_type':
            name = data['AT_name']

            try:
                val = int(data['AT_const_value'])
            except ValueError:
                val = int(data['AT_const_value'].split('(')[0])

            self.enums[parent_name][1][name] = val

        elif kind == 'TAG_subrange_type' and parent_kind == 'TAG_array_type':
            if 'AT_upper_bound' in data:
                try:
                    sz = int(data['AT_upper_bound'])
                except ValueError:
                    try:
                        sz = int(data['AT_upper_bound'].split('(')[0])
                    except ValueError:
                        # Give up
                        sz = 0
                sz += 1
            else:
                sz = 0

            tp = self.id_to_name[parent_name]
            self.id_to_name[parent_name] = ['array', sz, tp]
        else:
            pass
            #if kind != "NULL":
            #    print "Skipping unsupported tag %s" % kind

    def process_variable(self, data):
        return
        """Process a local variable."""
        if ('AT_name' in data and 'AT_decl_line' in data and
            'AT_type' in data):
            self.local_vars.append(
                (data['AT_name'], int(data['AT_decl_line']),
                 data['AT_decl_file'].split()[1], data['AT_type']) )

    def finalize(self):
        """Finalize the output."""
        if self.vtypes:
            self.vtypes = self.resolve_refs()
            self.all_vtypes.update(self.vtypes)
        if self.vars:
            self.vars = dict(((k, self.resolve(v)) for k, v in self.vars.items()))
            self.all_vars.update(self.vars)
        if self.local_vars:
            self.local_vars = [ (name, lineno, decl_file, self.resolve(tp)) for
                                (name, lineno, decl_file, tp) in self.local_vars ]
            self.all_local_vars += self.local_vars

        # Get rid of unneeded unknowns (shades of Rumsfeld here)
        # Needs to be done in fixed point fashion
        changed = True
        while changed:
            changed = False
            s = set()
            for m in self.all_vtypes:
                for t in self.all_vtypes[m][1].values():
                    s.add(self.get_deepest(t))
            for m in self.all_vars:
                s.add(self.get_deepest(self.all_vars[m][1]))
            for v in list(self.all_vtypes):
                if v.startswith('__unnamed_') and v not in s:
                    del self.all_vtypes[v]
                    changed = True

        # Merge the enums into the types directly:
        for t in self.all_vtypes:
            for m in list(self.all_vtypes[t][1]):
                memb = self.all_vtypes[t][1][m]
                d = self.get_deepest(memb)
                if d in self.enums:
                    sz = self.enums[d][0]
                    vals = dict((v, k) for k, v in self.enums[d][1].items())
                    self.all_vtypes[t][1][m] = self.deep_replace(
                        memb, [d],
                        ['Enumeration', dict(target = self.sz2tp[sz], choices = vals)]
                    )

        return self.all_vtypes

    def print_output(self):
        self.finalize()
        print "mac_types = {"

        for t in self.all_vtypes:
            print "  '%s': [ %#x, {" % (t, self.all_vtypes[t][0])
            for m in sorted(self.all_vtypes[t][1], key = lambda m: self.all_vtypes[t][1][m][0]):
                print "    '%s': [%#x, %s]," % (m, self.all_vtypes[t][1][m][0], self.all_vtypes[t][1][m][1])
            print "}],"
        print "}"
        print
        print "mac_gvars = {"
        for v in sorted(self.all_vars, key=lambda v: self.all_vars[v][0]):
            print "  '%s': [%#010x, %s]," % (v, self.all_vars[v][0], self.all_vars[v][1])
        print "}"

def MacProfileFactory(profpkg):

    vtypesvar = {}
    sysmapvar = {}

    memmodel, arch = "32bit", "x86"
    profilename = os.path.splitext(os.path.basename(profpkg.filename))[0]
 
    for f in profpkg.filelist:
        '''
        if f.filename.lower().endswith('.dwarf'):
            data = profpkg.read(f.filename)            
            res = self.parse_dwarf(data)
            vtypesvar.update(res)
            debug.debug("{2}: Found dwarf file {0} with {1} symbols".format(f.filename, len(vtypesvar.keys()), profilename))
        '''
        if 'symbol.dsymutil' in f.filename.lower():
            memmodel, sysmap = parse_dsymutil(profpkg.read(f.filename), "kernel")
            if memmodel == "64bit":
                arch = "x64"
            
            sysmapvar.update(sysmap)
            debug.debug("{2}: Found system file {0} with {1} symbols".format(f.filename, len(sysmapvar.keys()), profilename))

        elif f.filename.endswith(".vtypes"):
            v = exec_vtypes(profpkg.read(f.filename))                       
            vtypesvar.update(v)

    if not sysmapvar or not vtypesvar:
        # Might be worth throwing an exception here?
        return None

    '''
    def parse_dwarf(self, data):
        """Parse the dwarf file."""
        self._parser = DWARFParser()
        for line in data.splitlines():
            self._parser.feed_line(line)

        return self._parser.finalize()
    '''

    class AbstractMacProfile(obj.Profile):
        __doc__ = "A Profile for Mac " + profilename + " " + arch
        _md_os = "mac"
        _md_memory_model = memmodel

        def __init__(self, *args, **kwargs):
            self.sys_map = {}
            obj.Profile.__init__(self, *args, **kwargs)

        def clear(self):
            """Clear out the system map, and everything else"""
            self.sys_map = {}
            obj.Profile.clear(self)

        def reset(self):
            """Reset the vtypes, sysmap and apply modifications, then compile"""
            self.clear()
            self.load_vtypes()
            self.load_sysmap()
            self.load_modifications()
            self.compile()

        def load_vtypes(self):
            """Loads up the vtypes data"""
            ntvar = self.metadata.get('memory_model', '32bit')
            self.native_types = copy.deepcopy(self.native_mapping.get(ntvar))

            self.vtypes.update(vtypesvar)

        def load_sysmap(self):
            """Loads up the system map data"""
            self.sys_map.update(sysmapvar)

        # Returns a list of (name, addr)
        def get_all_symbols(self, module = "kernel"):
            """ Gets all the symbol tuples for the given module """
            ret = []

            symtable = self.sys_map

            if module in symtable:
                mod = symtable[module]

                for (name, addrs) in mod.items():
                    ret.append([name, addrs[0][0]])
            else:
                debug.info("All symbols  requested for non-existent module %s" % module)

            return ret

        def get_all_addresses(self, module = "kernel"):
            """ Gets all the symbol addresses for the given module """
            # returns a hash table for quick looks
            # the main use of this function is to see if an address is known
            ret = {}

            symbols = self.get_all_symbols(module)

            for (_name, addr) in symbols:
                ret[addr] = 1

            return ret

        def get_symbol_by_address(self, module, sym_address):
            ret = ""
            symtable = self.sys_map

            mod = symtable[module]

            for (name, addrs) in mod.items():

                for (addr, addr_type) in addrs:
                    if sym_address == addr:
                        ret = name
                        break

            return ret

        def get_all_symbol_names(self, module = "kernel"):
            symtable = self.sys_map

            if module in symtable:
                ret = symtable[module].keys()
            else:
                debug.error("get_all_symbol_names called on non-existent module")

            return ret

        def get_next_symbol_address(self, sym_name, module = "kernel"):
            """
            This is used to find the address of the next symbol in the profile
            For some data structures, we cannot determine their size automaticlaly so this
            can be used to figure it out on the fly
            """

            high_addr = 0xffffffffffffffff
            table_addr = self.get_symbol(sym_name, module = module)

            addrs = self.get_all_addresses(module = module)

            for addr in addrs.keys():

                if table_addr < addr < high_addr:
                    high_addr = addr

            return high_addr

        def get_symbol(self, sym_name, nm_type = "", sym_type = "", module = "kernel"):
            """Gets a symbol out of the profile
            
            sym_name -> name of the symbol
            nm_tyes  -> types as defined by 'nm' (man nm for examples)
            sym_type -> the type of the symbol (passing Pointer will provide auto deref)
            module   -> which module to get the symbol from, default is kernel, otherwise can be any name seen in 'lsmod'
    
            This fixes a few issues from the old static hash table method:
            1) Conflicting symbols can be handled, if a symbol is found to conflict on any profile, 
               then the plugin will need to provide the nm_type to differentiate, otherwise the plugin will be errored out
            2) Can handle symbols gathered from modules on disk as well from the static kernel
    
            symtable is stored as a hash table of:
            
            symtable[module][sym_name] = [(symbol address, symbol type), (symbol addres, symbol type), ...]
    
            The function has overly verbose error checking on purpose...
            """

            symtable = self.sys_map

            ret = None

            # check if the module is there...
            if module in symtable:

                mod = symtable[module]

                # check if the requested symbol is in the module
                if sym_name in mod:

                    sym_list = mod[sym_name]

                    # if a symbol has multiple definitions, then the plugin needs to specify the type
                    if len(sym_list) > 1:
                        if nm_type == "":
                            debug.error("Requested symbol {0:s} in module {1:s} has multiple definitions and no type given\n".format(sym_name, module))
                        else:
                            for (addr, stype) in sym_list:

                                if stype == nm_type:
                                    ret = addr
                                    break

                            if ret == None:
                                debug.error("Requested symbol {0:s} in module {1:s} of type {3:s} could not be found\n".format(sym_name, module, sym_type))

                    else:
                        # get the address of the symbol
                        ret = sym_list[0][0]

                else:
                    debug.debug("Requested symbol {0:s} not found in module {1:s}\n".format(sym_name, module))
            else:
                debug.info("Requested module {0:s} not found in symbol table\n".format(module))

            if ret and sym_type == "Pointer":
                # FIXME: change in 2.3 when truncation no longer occurs
                ret = ret & 0xffffffffffff

            return ret

    cls = AbstractMacProfile
    cls.__name__ = 'Mac' + profilename.replace('.', '_') + arch

    return cls

################################
# Track down the zip files
# Push them through the factory
# Check whether ProfileModifications will work

new_classes = []

for path in set(volatility.plugins.__path__):
    for path, _, files in os.walk(path):
        for fn in files:
            if zipfile.is_zipfile(os.path.join(path, fn)):
                new_classes.append(MacProfileFactory(zipfile.ZipFile(os.path.join(path, fn))))

'''
    def register_options(config):
        """Register profile specific options."""
        config.add_option("PROFILE_FILE", default = None, help = "The profile file to use for mac memory analysis. Must contain a dwarf file and a System map file.")
'''

class MacOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'mac'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.merge_overlay(mac_overlay)

class MacObjectClasses(obj.ProfileModification):

    conditions = {'os': lambda x: x == 'mac'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.object_classes.update({
            'VolatilityDTB': VolatilityDTB,
            'VolatilityMacIntelValidAS' : VolatilityMacIntelValidAS,
            'proc' : proc,
        })

mac_overlay = {
    'VOLATILITY_MAGIC': [None, {
        'DTB'           : [ 0x0, ['VolatilityDTB', dict(configname = "DTB")]],
        'IA32ValidAS'   : [ 0x0, ['VolatilityMacIntelValidAS']],
        'AMD64ValidAS'  : [ 0x0, ['VolatilityMacIntelValidAS']],
        }],

    'session' : [None, {
        's_login'          : [ None , ['String', dict(length = 255)]],
        }],
}

mac_vtypes = {
    'mach_trap'     : [ 16, {'mach_trap_function': [4, ['pointer', ['void']]]}]
}

class MacVTypes(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'mac'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.vtypes.update(mac_vtypes)


