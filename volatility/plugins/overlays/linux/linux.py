# Volatility
# Copyright (C) 2010 Brendan Dolan-Gavitt
# Copyright (c) 2011 Michael Cohen <scudette@gmail.com>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      brendandg@gatech.edu
@organization: Georgia Institute of Technology
"""

import os, struct, socket
import copy
import zipfile

import volatility.plugins
import volatility.plugins.overlays.basic as basic
import volatility.plugins.overlays.native_types as native_types
import volatility.exceptions as exceptions
import volatility.obj as obj
import volatility.debug as debug
import volatility.dwarf as dwarf
import volatility.scan as scan
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.flags as linux_flags
import volatility.addrspace as addrspace
import volatility.utils as utils
import volatility.protos as protos

x64_native_types = copy.deepcopy(native_types.x64_native_types)

x64_native_types['long'] = [8, '<q']
x64_native_types['unsigned long'] = [8, '<Q']

from operator import attrgetter

# Not entirely happy with this, but an overlay needs it
# The plugin (linux_apihooks) that uses the overlay checks for the distorm install
try:
    import distorm3
except ImportError:
    pass

class LinuxPermissionFlags(basic.Flags):
    """A Flags object for printing vm_area_struct permissions
    in a format like rwx or r-x"""

    def __str__(self):
        result = []
        value = self.v()
        keys = self.bitmap.keys()
        keys.sort()
        for k in keys:
            if value & (1 << self.bitmap[k]):
                result.append(k)
            else:
                result.append('-')

        return ''.join(result)

    def is_flag(self, flag):
        return self.v() & (1 << self.bitmap[flag])
    
    def is_executable(self):
        return self.is_flag('x')

    def is_readable(self):
        return self.is_flag('r')

    def is_writable(self):
        return self.is_flag('w')

linux_overlay = {
    'task_struct' : [None, {
        'comm'          : [ None , ['String', dict(length = 16)]],
        }],
    'in_ifaddr' : [None, {
        'ifa_label'     : [ None , ['String', dict(length = 16)]],
        }],
    'module'      : [None, {
        'name'          : [ None , ['String', dict(length = 60)]],
        }],
    'super_block' : [None, {
        's_id'          : [ None , ['String', dict(length = 32)]],
        }],
    'net_device'  : [None, {
        'name'          : [ None , ['String', dict(length = 16)]],
        }],
    'sockaddr_un' : [None, {
        'sun_path'      : [ None , ['String', dict(length = 108)]],
        }],
    'hlist_head' : [None, {
        'first'      : [ None , ['pointer', ['hlist_node']]],
        }],
    'tty_struct' : [None, {
        'name'      : [ None , ['String', dict(length = 64)]],
        }],
    'dentry' : [None, {
        'd_u'      : [ None , ['list_head', {}]],
    }],
    'VOLATILITY_MAGIC': [None, {
        'DTB'           : [ 0x0, ['VolatilityDTB', dict(configname = "DTB")]],
        'ArmValidAS'   :  [ 0x0, ['VolatilityLinuxARMValidAS']],
        'IA32ValidAS'  :  [ 0x0, ['VolatilityLinuxIntelValidAS']],
        'AMD64ValidAS'  :  [ 0x0, ['VolatilityLinuxIntelValidAS']],
        }],
    'vm_area_struct' : [ None, { 
        'vm_flags' : [ None, ['LinuxPermissionFlags', {'bitmap': {'r': 0, 'w': 1, 'x': 2}}]],
        'vm_end'    : [ None , ['unsigned long']],
        'vm_start'  : [ None , ['unsigned long']],
        }],
    }

intel_overlay = {
    'cpuinfo_x86' : [None, {
    'x86_model_id' : [ None , ['String', dict(length = 64)]],
    'x86_vendor_id' : [ None, ['String', dict(length = 16)]],
    }],
}

def parse_system_map(data, module):
    """Parse the symbol file."""
    sys_map = {}
    sys_map[module] = {}

    mem_model = None
    arch = "x86"    

    # get the system map
    for line in data.splitlines():
        (str_addr, symbol_type, symbol) = line.strip().split()

        try:
            sym_addr = long(str_addr, 16)

        except ValueError:
            continue

        if symbol == "arm_syscall":
            arch = "ARM"

        if not symbol in sys_map[module]:
            sys_map[module][symbol] = []

        sys_map[module][symbol].append([sym_addr, symbol_type])

    mem_model = str(len(str_addr) * 4) + "bit"
   
    if mem_model == "64bit" and arch == "x86":
        arch = "x64"
 
    return arch, mem_model, sys_map

def LinuxProfileFactory(profpkg):
    """ Takes in a zip file, spits out a LinuxProfile class

        The zipfile should include at least one .dwarf file
        and the appropriate system.map file.

        To generate a suitable dwarf file:
        dwarfdump -di vmlinux > output.dwarf
    """

    dwarfdata = None
    sysmapdata = None

    #  XXX Do we want to initialize this
    memmodel, arch = "32bit", "x86"
    profilename = os.path.splitext(os.path.basename(profpkg.filename))[0]

    for f in profpkg.filelist:
        if f.filename.lower().endswith('.dwarf'):
            dwarfdata = profpkg.read(f.filename)
        elif 'system.map' in f.filename.lower():
            sysmapdata = profpkg.read(f.filename)
            arch, memmodel, sysmap = parse_system_map(profpkg.read(f.filename), "kernel")

    if memmodel == "64bit":
        arch = "x64"

    if not sysmapdata or not dwarfdata:
        # Might be worth throwing an exception here?
        return None

    class AbstractLinuxProfile(obj.Profile):
        __doc__ = "A Profile for Linux " + profilename + " " + arch
        _md_os = "linux"
        _md_memory_model = memmodel
        _md_arch = arch
        # Override 64-bit native_types
        native_mapping = {'32bit': native_types.x86_native_types,
                          '64bit': x64_native_types}

        def __init__(self, *args, **kwargs):
            # change the name to catch any code referencing the old hash table
            self.sys_map = {}
            self.sym_addr_cache = {}
            self.shift_address = 0
            obj.Profile.__init__(self, *args, **kwargs)

        def clear(self):
            """Clear out the system map, and everything else"""
            self.sys_map = {}
            self.shift_address = 0
            obj.Profile.clear(self)

        def reset(self):
            """Reset the vtypes, sysmap and apply modifications, then compile"""
            self.clear()
            self.load_vtypes()
            self.load_sysmap()
            self.load_modifications()
            self.compile()

        def _merge_anonymous_members(self, vtypesvar):
            members_index = 1
            types_index = 1
            offset_index = 0

            try:
                for candidate in vtypesvar:
                    done = False
                    while not done:
                        if any(member.startswith('__unnamed_') for member in vtypesvar[candidate][members_index]):
                            for member in vtypesvar[candidate][members_index].keys():
                                if member.startswith('__unnamed_'):
                                    member_type = vtypesvar[candidate][members_index][member][types_index][0]
                                    location = vtypesvar[candidate][members_index][member][offset_index]
                                    vtypesvar[candidate][members_index].update(vtypesvar[member_type][members_index])
                                    for name in vtypesvar[member_type][members_index].keys():
                                        vtypesvar[candidate][members_index][name][offset_index] += location
                                    del vtypesvar[candidate][members_index][member]
                            # Don't update done because we'll need to check if any
                            # of the newly imported types need merging
                        else:
                            done = True
            except KeyError, e:
                import pdb
                pdb.set_trace()
                raise exceptions.VolatilityException("Inconsistent linux profile - unable to look up " + str(e))

        def load_vtypes(self):
            """Loads up the vtypes data"""
            ntvar = self.metadata.get('memory_model', '32bit')
            self.native_types = copy.deepcopy(self.native_mapping.get(ntvar))

            vtypesvar = dwarf.DWARFParser(dwarfdata).finalize()
            self._merge_anonymous_members(vtypesvar)
            self.vtypes.update(vtypesvar)
            debug.debug("{2}: Found dwarf file {0} with {1} symbols".format(f.filename, len(vtypesvar.keys()), profilename))

        def load_sysmap(self):
            """Loads up the system map data"""
            arch, _memmodel, sysmapvar = parse_system_map(sysmapdata, "kernel") 
            debug.debug("{2}: Found system file {0} with {1} symbols".format(f.filename, len(sysmapvar.keys()), profilename))

            self.sys_map.update(sysmapvar)

        def get_all_symbols(self, module = "kernel"):
            """ Gets all the symbol tuples for the given module """

            ret = []

            symtable = self.sys_map

            if module in symtable:
                mod = symtable[module]

                for (name, addrs) in mod.items():
                    addr = addrs[0][0]
                    if self.shift_address and addr:
                        addr = addr + self.shift_address

                    ret.append((name, addr))
            else:
                debug.info("All symbols requested for non-existent module %s" % module)

            return ret

        def get_all_addresses(self, module = "kernel"):
            """ Gets all the symbol addresses for the given module """

            # returns a hash table for quick looks
            # the main use of this function is to see if an address is known
            symbols = self.get_all_symbols(module)
            
            ret = {}

            for _name, addr in symbols:
                ret[addr] = 1

            return ret

        def _get_symbol_by_address(self, module, sym_address):
            ret = ""
            symtable = self.sys_map

            mod = symtable[module]

            for (name, addrs) in mod.items():

                for (addr, addr_type) in addrs:
                    if sym_address == addr + self.shift_address:
                        ret = name
                        break

            return ret

        def get_symbol_by_address(self, module, sym_address):
            key = "%s|%d" % (module, sym_address) 
        
            if key in self.sym_addr_cache:
                ret = self.sym_addr_cache[key] 
            else:
                ret = self._get_symbol_by_address(module, sym_address)
                self.sym_addr_cache[key] = ret

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

        def get_symbol(self, sym_name, nm_type = "", module = "kernel"):
            """Gets a symbol out of the profile
            
            sym_name -> name of the symbol
            nm_tyes  -> types as defined by 'nm' (man nm for examples)
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
                            debug.debug("Requested symbol {0:s} in module {1:s} has multiple definitions and no type given\n".format(sym_name, module))
                            return None
                        else:
                            for (addr, stype) in sym_list:

                                if stype == nm_type:
                                    ret = addr
                                    break

                            if ret == None:
                                debug.error("Requested symbol {0:s} in module {1:s} could not be found\n".format(sym_name, module))
                    else:
                        # get the address of the symbol
                        ret = sym_list[0][0]
                else:
                    debug.debug("Requested symbol {0:s} not found in module {1:s}\n".format(sym_name, module))
            else:
                debug.info("Requested module {0:s} not found in symbol table\n".format(module))

            if ret:
                ret = ret + self.shift_address

            return ret

        def get_symbol_type(self, sym_name, nm_type = "", module = "kernel"):
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
                            debug.debug("Requested symbol {0:s} in module {1:s} has multiple definitions and no type given\n".format(sym_name, module))
                            return None
                        else:
                            for (addr, stype) in sym_list:
                                if stype == nm_type:
                                    ret = addr
                                    break

                            if ret == None:
                                debug.error("Requested symbol {0:s} in module {1:s} could not be found\n".format(sym_name, module))
                    else:
                        # get the type of the symbol
                        ret = sym_list[0][1]
                else:
                    debug.debug("Requested symbol {0:s} not found in module {1:s}\n".format(sym_name, module))
            else:
                debug.info("Requested module {0:s} not found in symbol table\n".format(module))

            return ret


    cls = AbstractLinuxProfile
    cls.__name__ = 'Linux' + profilename.replace('.', '_') + arch

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
                new_classes.append(LinuxProfileFactory(zipfile.ZipFile(os.path.join(path, fn))))

################################

# really 'file' but don't want to mess with python's version
class linux_file(obj.CType):

    @property
    def dentry(self):
        if hasattr(self, "f_dentry"):
            ret = self.f_dentry
        else:
            ret = self.f_path.dentry

        return ret

    @property
    def vfsmnt(self):
        if hasattr(self, "f_vfsmnt"):
            ret = self.f_vfsmnt
        else:
            ret = self.f_path.mnt

        return ret

# FIXME - walking backwards has not been thorougly tested
class hlist_node(obj.CType):
    """A hlist_node makes a doubly linked list."""
    def list_of_type(self, obj_type, member, offset = -1, forward = True, head_sentinel = True):
        if not self.is_valid():
            return

        ## Get the first element
        if forward:
            nxt = self.m("next").dereference()
        else:
            nxt = self.pprev.dereference().dereference()

        offset = self.obj_vm.profile.get_obj_offset(obj_type, member)

        seen = set()
        if head_sentinel:
            # We're a header element and not to be included in the list
            seen.add(self.obj_offset)

        while nxt.is_valid() and nxt.obj_offset not in seen:
            ## Instantiate the object
            item = obj.Object(obj_type, offset = nxt.obj_offset - offset,
                                    vm = self.obj_vm,
                                    parent = self.obj_parent,
                                    name = obj_type)

            seen.add(nxt.obj_offset)

            yield item

            if forward:
                nxt = item.m(member).m("next").dereference()
            else:
                nxt = item.m(member).pprev.dereference().dereference()


    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.next) or bool(self.pprev)

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_name, self.obj_name)

class list_head(obj.CType):
    """A list_head makes a doubly linked list."""
    def list_of_type(self, obj_type, member, offset = -1, forward = True, head_sentinel = True):
        if not self.is_valid():
            return

        ## Get the first element
        if forward:
            nxt = self.next.dereference()
        else:
            nxt = self.prev.dereference()

        offset = self.obj_vm.profile.get_obj_offset(obj_type, member)

        seen = set()
        if head_sentinel:
            # We're a header element and not to be included in the list
            seen.add(self.obj_offset)

        while nxt.is_valid() and nxt.obj_offset not in seen:
            ## Instantiate the object
            item = obj.Object(obj_type, offset = nxt.obj_offset - offset,
                                    vm = self.obj_vm,
                                    parent = self.obj_parent,
                                    name = obj_type)

            seen.add(nxt.obj_offset)

            yield item

            if forward:
                nxt = item.m(member).m("next").dereference()
            else:
                nxt = item.m(member).prev.dereference()

    
    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.next) or bool(self.prev)

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_name, self.obj_name)

class hlist_bl_node(obj.CType):
    """A list_head makes a doubly linked list."""
    def list_of_type(self, obj_type, member, offset = -1, forward = True, head_sentinel = True):
        if not self.is_valid():
            return

        ## Get the first element
        if forward:
            nxt = self.next.dereference()
        else:
            nxt = self.prev.dereference()

        offset = self.obj_vm.profile.get_obj_offset(obj_type, member)

        seen = set()
        if head_sentinel:
            # We're a header element and not to be included in the list
            seen.add(self.obj_offset)

        while nxt.is_valid() and nxt.obj_offset not in seen:
            ## Instantiate the object
            item = obj.Object(obj_type, offset = nxt.obj_offset - offset,
                                    vm = self.obj_vm,
                                    parent = self.obj_parent,
                                    name = obj_type)

            seen.add(nxt.obj_offset)

            yield item

            if forward:
                nxt = item.m(member).next.dereference()
            else:
                nxt = item.m(member).prev.dereference()

    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.next) or bool(self.prev)

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_name, self.obj_name)


class files_struct(obj.CType):

    def get_fds(self):
        if hasattr(self, "fdt"):
            fdt = self.fdt
            ret = fdt.fd.dereference()
        else:
            ret = self.fd.dereference()

        return ret

    def get_max_fds(self):
        if hasattr(self, "fdt"):
            ret = self.fdt.max_fds
        else:
            ret = self.max_fds

        return ret

class kernel_param(obj.CType):

    @property
    def get(self):

        if self.members.get("get"):
            ret = self.m("get")
        else:
            ret = self.ops.get

        return ret

class kparam_array(obj.CType):

    @property
    def get(self):

        if self.members.get("get"):
            ret = self.m("get")
        else:
            ret = self.ops.get

        return ret

class gate_struct64(obj.CType):

    @property
    def Address(self):
        low    = self.offset_low
        middle = self.offset_middle
        high   = self.offset_high

        ret = (high << 32) | (middle << 16) | low

        return ret

class desc_struct(obj.CType):

    @property
    def Address(self):
        return (self.b & 0xffff0000) | (self.a & 0x0000ffff)

class module_sect_attr(obj.CType):
    @property
    def sect_name(self):
        if type(self.m("name")) == obj.Array:
            name = obj.Object("String", offset = self.m("name").obj_offset, vm = self.obj_vm, length = 32)
        else:
            name = self.name.dereference_as("String", length = 255)

        return str(name)       

class sock(obj.CType):
    @property
    def sk_node(self):
        return self.__sk_common.skc_node #pylint: disable-msg=W0212

class inet_sock(obj.CType):
    """Class for an internet socket object"""

    @property
    def protocol(self):
        """Return the protocol string (i.e. IPv4, IPv6)"""
        return protos.protos.get(self.sk.sk_protocol.v(), "UNKNOWN")

    @property
    def state(self):
        state = self.sk.__sk_common.skc_state #pylint: disable-msg=W0212

        if 0 <= state < len(linux_flags.tcp_states):
            ret = linux_flags.tcp_states[state]
        else:
            ret = "" 

        return ret
    
    @property
    def src_port(self):
        if hasattr(self, "sport"):
            return socket.htons(self.sport)
        elif hasattr(self, "inet_sport"):
            return socket.htons(self.inet_sport)
        else:
            return None

    @property
    def dst_port(self):
        if hasattr(self, "sk") and hasattr(self.sk, "__sk_common") and hasattr(self.sk.__sk_common, "skc_portpair"):
            return socket.htons(self.sk.__sk_common.skc_portpair & 0xffff) #pylint: disable-msg=W0212  
        elif hasattr(self, "dport"):
            return socket.htons(self.dport)
        elif hasattr(self, "inet_dport"):
            return socket.htons(self.inet_dport)
        elif hasattr(self, "sk") and hasattr(self.sk, "__sk_common") and hasattr(self.sk.__sk_common, "skc_dport"):
            return socket.htons(self.sk.__sk_common.skc_dport) #pylint: disable-msg=W0212
        else:
            return None

    @property
    def src_addr(self):

        if self.sk.__sk_common.skc_family == socket.AF_INET:
            # FIXME: Consider using kernel version metadata rather than checking hasattr
            if hasattr(self, "rcv_saddr"):
                saddr = self.rcv_saddr
            elif hasattr(self, "inet_rcv_saddr"):
                saddr = self.inet_rcv_saddr
            else:
                saddr = self.sk.__sk_common.skc_rcv_saddr

            return saddr.cast("IpAddress")
        else:
            return self.pinet6.saddr.cast("Ipv6Address")

    @property
    def dst_addr(self):
        if self.sk.__sk_common.skc_family == socket.AF_INET:
            # FIXME: Consider using kernel version metadata rather than checking hasattr
            if hasattr(self, "daddr") and self.daddr:
                daddr = self.daddr
            elif hasattr(self, "inet_daddr") and self.inet_daddr:
                daddr = self.inet_daddr
            else:
                daddr = self.sk.__sk_common.skc_daddr

            return daddr.cast("IpAddress")
        else:
            if hasattr(self.pinet6, "daddr"):
                return self.pinet6.daddr.cast("Ipv6Address")
            else:
                return self.sk.__sk_common.skc_v6_daddr.cast("Ipv6Address") #pylint: disable-msg=W0212

class tty_ldisc(obj.CType):

    @property
    def ops(self):
        check = self.members.get("ops")
        if check:
            ret = self.m('ops')
        else:
            ret = self

        return ret

class in_device(obj.CType):
    
    def devices(self):
        cur = self.ifa_list
        while cur != None and cur.is_valid():
            yield cur
            cur = cur.ifa_next

class net_device(obj.CType):
    
    @property
    def mac_addr(self):        
        macaddr = "00:00:00:00:00:00"

        if self.members.has_key("perm_addr"):
            hwaddr = self.perm_addr
            macaddr = ":".join(["{0:02x}".format(x) for x in hwaddr][:6])
        
        if macaddr == "00:00:00:00:00:00":
            if type(self.dev_addr) == volatility.obj.Pointer:
                addr = self.dev_addr.v()
            else:
                addr = self.dev_addr.obj_offset
    
            hwaddr = self.obj_vm.zread(addr, 6)
            macaddr = ":".join(["{0:02x}".format(ord(x)) for x in hwaddr][:6])
                        
        return macaddr

    @property
    def promisc(self):
        return self.flags & 0x100 == 0x100 # IFF_PROMISC

class module_struct(obj.CType):
    @property   
    def module_core(self):
        if hasattr(self, "core_layout"):
            ret = self.m("core_layout").m("base")
        else:
            ret = self.m("module_core")

        return ret

    @property
    def module_init(self):
        if hasattr(self, "init_layout"):
            ret = self.m("init_layout").m("base")
        else:
            ret = self.m("module_init")
    
        return ret

    @property
    def init_size(self):
        if hasattr(self, "init_layout"):
            ret = self.m("init_layout").m("size")
        else:
            ret = self.m("init_size")

        return ret
 
    @property 
    def core_size(self):
        if hasattr(self, "core_layout"):
            ret = self.m("core_layout").m("size")
        else:
            ret = self.m("core_size")

        return ret
        
    def _get_sect_count(self, grp):
        arr = obj.Object(theType = 'Array', offset = grp.attrs, vm = self.obj_vm, targetType = 'Pointer', count = 25)

        idx = 0
        while arr[idx]:
            idx = idx + 1

        return idx

    def get_sections(self):
        if hasattr(self.sect_attrs, "nsections"):
            num_sects = self.sect_attrs.nsections
        else:
            num_sects = self._get_sect_count(self.sect_attrs.grp)

        attrs = obj.Object(theType = 'Array', offset = self.sect_attrs.attrs.obj_offset, vm = self.obj_vm, targetType = 'module_sect_attr', count = num_sects)

        for attr in attrs:
            yield attr        

    def get_param_val(self, param, _over = 0):
        ints = {
                self.obj_vm.profile.get_symbol("param_get_invbool") : "int",
                self.obj_vm.profile.get_symbol("param_get_bool") : "int",
                self.obj_vm.profile.get_symbol("param_get_int") : "int",
                self.obj_vm.profile.get_symbol("param_get_ulong") : "unsigned long",
                self.obj_vm.profile.get_symbol("param_get_long") : "long",
                self.obj_vm.profile.get_symbol("param_get_uint") : "unsigned int",
                self.obj_vm.profile.get_symbol("param_get_ushort") : "unsigned short",
                self.obj_vm.profile.get_symbol("param_get_short") : "short",
                self.obj_vm.profile.get_symbol("param_get_byte") : "char",
               }

        getfn = param.get

        if getfn == 0:
            val = ""

        elif getfn == self.obj_vm.profile.get_symbol("param_array_get"):
            val = ""
            arr = param.arr
            overwrite = param.arr

            if arr.num:
                maxi = arr.num.dereference()
            else:
                maxi = arr.max

            for i in range(maxi):
                if i > 0:
                    val = val + ","

                arg = arr.elem + arr.elemsize * i
                overwrite.arg = arg

                mret = self.get_param_val(overwrite)
                val = val + str(mret or '')

        elif getfn == self.obj_vm.profile.get_symbol("param_get_string"):
            val = param.str.dereference_as("String", length = param.str.maxlen)

        elif getfn == self.obj_vm.profile.get_symbol("param_get_charp"):
            addr = obj.Object("Pointer", offset = param.arg, vm = self.obj_vm)
            if addr == 0:
                val = "(null)"
            else:
                val = addr.dereference_as("String", length = 256)

        elif getfn.v() in ints:
            val = obj.Object(ints[getfn.v()], offset = param.arg, vm = self.obj_vm)

            if getfn == self.obj_vm.profile.get_symbol("param_get_bool"):
                if val:
                    val = 'Y'
                else:
                    val = 'N'

            if getfn == self.obj_vm.profile.get_symbol("param_get_invbool"):
                if val:
                    val = 'N'
                else:
                    val = 'Y'

        else:
            return None

        return val

    def get_params(self):
        if not hasattr(self, "kp"):
            return ""

        params = ""
        param_array = obj.Object(theType = 'Array', offset = self.kp, vm = self.obj_vm, targetType = 'kernel_param', count = self.num_kp)
        
        for param in param_array:
            val = self.get_param_val(param)
            params = params + "{0}={1} ".format(param.name.dereference_as("String", length = 255), val)

        return params

    def get_symbols(self):
        ret_syms = []

        if self.obj_vm.profile.metadata.get('arch').lower() == 'x64':
            struct_name = "elf64_sym"
        else:
            struct_name = "elf32_sym"

        syms = obj.Object(theType = "Array", targetType = struct_name, offset = self.symtab, count = self.num_symtab + 1, vm = self.obj_vm)           

        for sym_struct in syms:
            sym_name_addr = self.strtab + sym_struct.st_name

            sym_name = self.obj_vm.read(sym_name_addr, 64)
            if not sym_name:
                continue
            
            idx = sym_name.index("\x00")
            if idx != -1:
                sym_name = sym_name[:idx]

            if sym_name != "":
                ret_syms.append((str(sym_name), sym_struct.st_value.v()))

        return ret_syms

    def get_symbol_for_address(self, wanted_address):
        ret = None

        for (sym_name, sym_addr) in self.get_symbols():
            if sym_addr == wanted_address:
                ret = sym_name
                break

        return ret    

    def get_symbol(self, wanted_sym_name):
        ret = None

        for (sym_name, sym_addr) in self.get_symbols():
            if wanted_sym_name == sym_name:
                ret = sym_addr
                break

        return ret       
   
    @property
    def symtab(self):
        if hasattr(self, "kallsyms"):
            ret = self.kallsyms.symtab
        else:
            ret = self.m("symtab")

        return ret 
 
    @property
    def num_symtab(self):
        if hasattr(self, "kallsyms"):
            ret = self.kallsyms.num_symtab.v()
        else:
            ret = self.m("num_symtab").v()

        return ret   

    def is_valid(self):
        valid = False

        if self.state.v() in [0, 1, 2] and \
           self.core_size >= 1 and self.core_size <= 1000000 and \
           self.core_text_size >= 1 and self.core_text_size <= 1000000:
        
            s = self.obj_vm.read(self.name.obj_offset, 64)
            if s:
                idx = s.find("\x00")

                if idx > 1:
                    good = True
                    name = s[:idx]
                    for n in name:
                        if not (32 < ord(n) < 127):
                            good = False
                            break

                    if good and self.module_core.is_valid():
                        valid = True

        return valid

class vm_area_struct(obj.CType):
    def vm_name(self, task):
        if self.vm_file:
            fname = linux_common.get_path(task, self.vm_file)
            if fname == []:
                fname = ""

        elif self.vm_start <= task.mm.start_brk and self.vm_end >= task.mm.brk:
            fname = "[heap]"
        elif self.vm_start <= task.mm.start_stack and self.vm_end >= task.mm.start_stack:
            fname = "[stack]"
        elif hasattr(self.vm_mm.context, "vdso") and self.vm_start == self.vm_mm.context.vdso:
            fname = "[vdso]"
        else:
            fname = "Anonymous Mapping"

        return fname

    extended_flags = {
        0x00000001 : "VM_READ",
        0x00000002 : "VM_WRITE",
        0x00000004 : "VM_EXEC",
        0x00000008 : "VM_SHARED",
        0x00000010 : "VM_MAYREAD",
        0x00000020 : "VM_MAYWRITE",
        0x00000040 : "VM_MAYEXEC",
        0x00000080 : "VM_MAYSHARE",
        0x00000100 : "VM_GROWSDOWN",
        0x00000200 : "VM_NOHUGEPAGE",
        0x00000400 : "VM_PFNMAP",
        0x00000800 : "VM_DENYWRITE",
        0x00001000 : "VM_EXECUTABLE",
        0x00002000 : "VM_LOCKED",
        0x00004000 : "VM_IO",
        0x00008000 : "VM_SEQ_READ",
        0x00010000 : "VM_RAND_READ",        
        0x00020000 : "VM_DONTCOPY", 
        0x00040000 : "VM_DONTEXPAND",
        0x00080000 : "VM_RESERVED",
        0x00100000 : "VM_ACCOUNT",
        0x00200000 : "VM_NORESERVE",
        0x00400000 : "VM_HUGETLB",
        0x00800000 : "VM_NONLINEAR",        
        0x01000000 : "VM_MAPPED_COP__VM_HUGEPAGE",
        0x02000000 : "VM_INSERTPAGE",
        0x04000000 : "VM_ALWAYSDUMP",
        0x08000000 : "VM_CAN_NONLINEAR",
        0x10000000 : "VM_MIXEDMAP",
        0x20000000 : "VM_SAO",
        0x40000000 : "VM_PFN_AT_MMAP",
        0x80000000 : "VM_MERGEABLE",
    }

    def _parse_perms(self, flags):
        fstr = ""

        for mask in sorted(self.extended_flags.keys()):
            if flags & mask == mask:
                fstr = fstr + self.extended_flags[mask] + "|"
 
        if len(fstr) != 0:
            fstr = fstr[:-1]

        return fstr

    def protection(self):
        return self._parse_perms(self.vm_flags.v() & 0b1111) 

    def flags(self):
        return self._parse_perms(self.vm_flags.v())

    # used by malfind
    def is_suspicious(self):
        ret = False        

        flags_str  = self.protection()
      
        if flags_str.find("VM_READ|VM_WRITE|VM_EXEC") != -1:
            ret = True 
            
        elif flags_str == "VM_READ|VM_EXEC" and not self.vm_file:
            ret = True

        return ret

    def info(self, task):
        if self.vm_file:
            inode = self.vm_file.dentry.d_inode
            major, minor = inode.i_sb.major, inode.i_sb.minor
            ino = inode.i_ino
            pgoff = self.vm_pgoff << 12
        else:
            (major, minor, ino, pgoff) = [0] * 4

        fname = self.vm_name(task)

        if fname == "Anonymous Mapping":
            fname = ""

        return fname, major, minor, ino, pgoff 

class task_struct(obj.CType):
    def is_valid_task(self):

        ret = self.fs.v() != 0 and self.files.v() != 0

        if ret and self.members.get("cred"):
            ret = self.cred.is_valid()

        return ret
    
    @property
    def comm(self):
        c = self.m("comm")
        return c.replace("\x1b", "\\x1b")

    def getcwd(self):
        rdentry = self.fs.get_root_dentry()
        rmnt    = self.fs.get_root_mnt()
        pdentry = self.fs.get_pwd_dentry()
        pmnt    = self.fs.get_pwd_mnt()
          
        path = linux_common.do_get_path(rdentry, rmnt, pdentry, pmnt) 

        if path == []:
            path = ""

        return path

    def get_elf(self, elf_addr):
        sects = {}
        ret = ""

        proc_as = self.get_process_address_space()

        if proc_as == None:
            return ret
  
        elf_hdr = obj.Object("elf_hdr", offset = elf_addr, vm = proc_as)

        if not elf_hdr.is_valid():
            return ""

        for phdr in elf_hdr.program_headers():
            if str(phdr.p_type) != 'PT_LOAD':
                continue

            start = phdr.p_vaddr
            sz    = phdr.p_memsz
            end = start + sz

            if start % 4096:
                start = start & ~0xfff

            if end % 4096:
                end = (end & ~0xfff) + 4096

            real_size = end - start

            sects[start] = real_size
 
        last_end = -1

        for start in sorted(sects.keys()):
            read_size = sects[start]

            if last_end != -1 and last_end != start + read_size:
                debug.error("busted LOAD segments in %s | %d -> %x != %x + %x" % (task.comm, task.pid, last_end, start, read_size))

            buf = proc_as.zread(start, read_size)

            ret = ret + buf

        return ret

    @property
    def uid(self):
        ret = self.members.get("uid")
        if ret is None:
            if hasattr(self.cred.uid, "val"):
                ret = self.cred.uid.val
            else:
                ret = self.cred.uid
        else:
            ret = self.m("uid")

        if type(ret) in [obj.CType, obj.NativeType]:
            ret = ret.v()

        return ret

    @property
    def gid(self):
        ret = self.members.get("gid")
        if ret is None:
            gid = self.cred.gid
            if hasattr(gid, 'counter'):
                ret = obj.Object("int", offset = gid.v(), vm = self.obj_vm)
            elif hasattr(gid, "val"):
                ret = gid.val
            else:
                ret = gid
        else:
            ret = self.m("gid")

        if type(ret) == obj.CType:
            ret = ret.v()

        return ret

    @property
    def euid(self):
        ret = self.members.get("euid")
        if ret is None:
            ret = self.cred.euid
        else:
            ret = self.m("euid")

        if type(ret) == obj.CType:
            ret = ret.v()

        return ret

    def find_heap_vma(self):
        ret = None

        for vma in self.get_proc_maps():
            # find the data section of bash
            if vma.vm_start <= self.mm.start_brk and vma.vm_end >= self.mm.brk:
                ret = vma
                break

        return ret

    def bash_hash_entries(self):
        nbuckets_offset = self.obj_vm.profile.get_obj_offset("_bash_hash_table", "nbuckets") 
        
        heap_vma = self.find_heap_vma()

        if heap_vma == None:
            debug.debug("Unable to find heap for pid %d" % self.pid)
            return

        proc_as = self.get_process_address_space()
        if proc_as == None:
            return

        for off in self.search_process_memory(["\x40\x00\x00\x00"], heap_only=True):
            # test the number of buckets
            htable = obj.Object("_bash_hash_table", offset = off - nbuckets_offset, vm = proc_as)
            
            for ent in htable:
                yield ent            

            off = off + 1

    def ldrmodules(self):
        proc_maps = {}
        dl_maps   = {}
        seen_starts = {}

        proc_as = self.get_process_address_space()        
        if proc_as == None:
            return

        # get libraries from proc_maps
        for vma in self.get_proc_maps():
            sig = proc_as.read(vma.vm_start, 4)
            
            if sig == "\x7fELF":
                flags = str(vma.vm_flags)
       
                if flags in ["rw-", "r--"]:
                    continue 

                fname = vma.vm_name(self)

                if fname == "[vdso]":
                    continue

                start = vma.vm_start.v()

                proc_maps[start]   = fname
                seen_starts[start] = 1   

        # get libraries from userland
        for so in self.get_libdl_maps():
            if so.l_addr == 0x0 or len(str(so.l_name)) == 0:
                continue

            start = so.l_addr.v()

            dl_maps[start] = str(so.l_name)
            seen_starts[start] = 1

        for start in seen_starts:
            vm_name = ""
            
            if start in proc_maps:    
                pmaps = "True"
                vm_name = proc_maps[start]
            else:
                pmaps = "False"

            if start in dl_maps:
                dmaps = "True"
                
                # we prefer the name from proc_maps as it is within kernel memory
                if vm_name == "":
                    vm_name = dl_maps[start]
            else:
                dmaps = "False"

            yield (start, vm_name, pmaps, dmaps)

    def plt_hook_info(self):
        elfs = dict()

        for elf, elf_start, elf_end, soname, needed in self.elfs():
            elfs[(self, soname)] = (elf, elf_start, elf_end, needed)

        for k, v in elfs.iteritems():
            task, soname = k
            elf, elf_start, elf_end, needed = v
          
            if elf._get_typename("hdr") == "elf32_hdr":
                elf_arch = 32
            else:
                elf_arch = 64
         
            needed_expanded = set([soname])
            if (task, None) in elfs:
                needed_expanded.add(None)
            # jmp slot can point to ELF itself if the fn hasn't been called yet (RTLD_LAZY)
            # can point to main binary (None above) if this is a plugin-style symbol
            while len(needed) > 0:
                dep = needed.pop(0)
                needed_expanded.add(dep)
                try:
                    needed += set(elfs[(task, dep)][3]) - needed_expanded
                except KeyError:
                    needed_expanded.remove(dep)

            for reloc in elf.relocations():
                rsym = elf.relocation_symbol(reloc)

                if rsym == None:
                    continue

                symbol_name = elf.symbol_name(rsym)
                if symbol_name == None:
                    symbol_name = "<N/A>"

                offset = reloc.r_offset
               
                if offset < elf_start:
                    offset = elf_start + offset

                if elf_arch == 32:
                    addr = obj.Object("unsigned int", offset = offset, vm = elf.obj_vm)
                else:
                    addr = obj.Object("unsigned long long", offset = offset, vm = elf.obj_vm)
                
                match = False
                for dep in needed_expanded:
                    _, dep_start, dep_end, _ = elfs[(task, dep)]
                    if addr >= dep_start and addr < dep_end:
                        match = dep

                hookdesc = ''
                vma = None
                for i in task.get_proc_maps():
                    if addr >= i.vm_start and addr < i.vm_end:
                        vma = i
                        break                    
                if vma:
                    if vma.vm_file:
                        hookdesc = linux_common.get_path(task, vma.vm_file)
                    else:
                        hookdesc = '[{0:x}:{1:x},{2}]'.format(vma.vm_start, vma.vm_end, vma.vm_flags)
 
                if hookdesc == "":
                        hookdesc = 'invalid memory'
                
                if match != False:
                    if match == soname:
                        hookdesc = '[RTLD_LAZY]'
                    hooked = False 
                
                else:
                    hooked = True

                yield soname, elf, elf_start, elf_end, addr, symbol_name, hookdesc, hooked
    
    def _is_api_hooked(self, sym_addr, proc_as):
        hook_type = None 
        addr = None    
        counter   = 1 
        prev_op = None

        if self.obj_vm.profile.metadata.get('memory_model', '32bit') == '32bit':
            mode = distorm3.Decode32Bits
        else:
            mode = distorm3.Decode64Bits

        data = proc_as.read(sym_addr, 24)
    
        for op in distorm3.Decompose(sym_addr, data, mode):
            if not op or not op.valid:
                continue

            if op.mnemonic == "JMP":
                hook_type = "JMP"
                addr = 0 # default in case we cannot extract               

                # check for a mov reg, addr; jmp reg;
                if prev_op and prev_op.mnemonic == "MOV" and prev_op.operands[0].type == 'Register' and op.operands[0].type == 'Register':
                    prev_name = prev_op.operands[0].name
                    
                    # same register
                    if prev_name == op.operands[0].name:
                        addr = prev_op.operands[1].value                        

                else:
                    addr = op.operands[0].value

            elif op.mnemonic == "CALL":
                hook_type = "CALL"
                addr = op.operands[0].value

            # push xxxx; ret;
            elif counter == 2 and op.mnemonic == "RET":
                if prev_op.mnemonic == "MOV" and prev_op.operands[0].type == 'Register' and  prev_op.operands[0].name in ["RAX", "EAX"]:
                    break

                elif prev_op.mnemonic == "XOR" and prev_op.operands[0].type == 'Register' and prev_op.operands[1].type == 'Register':
                    break

                elif prev_op.mnemonic == "MOV" and prev_op.operands[0].type == 'Register' and  prev_op.operands[1].type == 'Register':
                    break
                
                hook_type = "RET"
                addr = sym_addr

            if hook_type:
                break

            counter = counter + 1
            if counter == 4:
                break

            prev_op = op

        if hook_type and addr:
            ret = hook_type, addr
        else:
            ret = None

        return ret

    def _get_hooked_name(self, addr):
        hook_vma = None        
        hookdesc = "<Unknown mapping>"

        for i in self.get_proc_maps():
            if addr >= i.vm_start and addr < i.vm_end:
                hook_vma = i
                break          
          
        if hook_vma:
            if hook_vma.vm_file:
                hookdesc = linux_common.get_path(self, hook_vma.vm_file)
            else:
                hookdesc = '[{0:x}:{1:x},{2}]'.format(hook_vma.vm_start, hook_vma.vm_end, hook_vma.vm_flags)
        
        return (hook_vma, hookdesc)

    def apihook_info(self):
        for soname, elf, elf_start, elf_end, addr, symbol_name, _, plt_hooked in self.plt_hook_info():
               
            is_hooked = self._is_api_hooked(addr, elf.obj_vm)

            if is_hooked:
                hook_type, hook_addr = is_hooked
            else:
                continue

            (hook_vma, hookdesc) = self._get_hooked_name(addr)
            (hook_func_vma, hookfuncdesc) = self._get_hooked_name(hook_addr)

            if not hook_vma or not hook_func_vma or hook_vma.vm_start != hook_func_vma.vm_start:
                yield hookdesc, symbol_name, addr, hook_type, hook_addr, hookfuncdesc

    def bash_history_entries(self):
        proc_as = self.get_process_address_space()
        if not proc_as:
            return

        # Keep a bucket of history objects so we can order them
        history_entries = []

        # Brute force the history list of an address isn't provided 
        ts_offset = proc_as.profile.get_obj_offset("_hist_entry", "timestamp") 

        # Are we dealing with 32 or 64-bit pointers
        if proc_as.profile.metadata.get('memory_model', '32bit') == '32bit':
            pack_format = "I"
        else:
            pack_format = "Q"

        bang_addrs = []

        # Look for strings that begin with pound/hash on the process heap 
        for ptr_hash in self.search_process_memory(["#"], heap_only = True):
            # Find pointers to this strings address, also on the heap 
            bang_addrs.append(struct.pack(pack_format, ptr_hash))

        for (idx, ptr_string) in enumerate(self.search_process_memory(bang_addrs, heap_only = True)):   
            # Check if we found a valid history entry object 
            hist = obj.Object("_hist_entry", 
                              offset = ptr_string - ts_offset, 
                              vm = proc_as)

            if hist.is_valid():
                history_entries.append(hist)
                       
        # Report everything we found in order
        for hist in sorted(history_entries, key = attrgetter('time_as_integer')):
            yield hist              

    def psenv(self):
        env = ""

        if self.mm:
            # set the as with our new dtb so we can read from userland
            proc_as = self.get_process_address_space()
            if proc_as == None:
                env = ""
            else:
                # read argv from userland
                start = self.mm.env_start.v()

                env = proc_as.read(start, self.mm.env_end - self.mm.env_start + 10)
                
        if env:
            ents = env.split("\x00")
            for varstr in ents:
                eqidx = varstr.find("=")

                if eqidx == -1:
                    continue

                key = varstr[:eqidx]
                val = varstr[eqidx+1:]

                yield (key, val) 

    def _dynamic_env(self, proc_as, pack_format, addr_sz):
        for vma in self.get_proc_maps():
            if not (vma.vm_file and str(vma.vm_flags) == "rw-"):
                continue
            
            fname = vma.info(self)[0]

            if fname.find("ld") == -1 and fname != "/bin/bash":
                continue

            env_start = 0
            for off in range(vma.vm_start, vma.vm_end):
                # check the first index
                addrstr = proc_as.read(off, addr_sz)
                if not addrstr or len(addrstr) != addr_sz:
                    continue
                addr = struct.unpack(pack_format, addrstr)[0]
                # check first idx...
                if addr:
                    firstaddrstr = proc_as.read(addr, addr_sz)
                    if not firstaddrstr or len(firstaddrstr) != addr_sz:
                        continue
                    firstaddr = struct.unpack(pack_format, firstaddrstr)[0]
                    buf = proc_as.read(firstaddr, 64)
                    if not buf:
                        continue
                    eqidx = buf.find("=")
                    if eqidx > 0:
                        nullidx = buf.find("\x00")
                        # single char name, =
                        if nullidx >= eqidx:
                            env_start = addr
            
            if env_start == 0:
                continue

            envars = obj.Object(theType="Array", targetType="Pointer", vm=proc_as, offset=env_start, count=256)
            for var in envars:
                if var:
                    sizes = [8, 16, 32, 64, 128, 256, 384, 512, 1024, 2048, 4096]
                    good_varstr = None

                    for size in sizes:
                        varstr = proc_as.read(var, size)
                        if not varstr:
                            continue

                        eqidx = varstr.find("=")
                        idx = varstr.find("\x00")

                        if idx == -1 or eqidx == -1 or idx < eqidx:
                            continue
                    
                        good_varstr = varstr
                        break
                
                    if good_varstr:        
                        good_varstr = good_varstr[:idx]

                        key = good_varstr[:eqidx]
                        val = good_varstr[eqidx+1:]
                        
                        yield (key, val) 
                    else:
                        break

    def _shell_variables(self, proc_as, pack_format, addr_sz):
        bash_was_last = False
        for vma in self.get_proc_maps():
            if vma.vm_file:
                fname = vma.info(self)[0]
       
                if fname.endswith("/bin/bash"):
                    bash_was_last = True
                else:
                    bash_was_last = False
            
            # we are looking for the bss of bash 
            if vma.vm_file or str(vma.vm_flags) != "rw-":
                continue
            
            # we are looking for the bss of bash 
            if bash_was_last == False:
                continue
        
            nbuckets_offset = self.obj_vm.profile.get_obj_offset("_bash_hash_table", "nbuckets") 

            for off in range(vma.vm_start, vma.vm_end, 4):
                ptr_test = proc_as.read(off, addr_sz)
                if not ptr_test:
                    continue

                ptr = struct.unpack(pack_format, ptr_test)[0]
                
                ptr_test2 = proc_as.read(ptr + 20, addr_sz)
                if not ptr_test2:
                    continue

                ptr2 = struct.unpack(pack_format, ptr_test2)[0]
                
                test = proc_as.read(ptr2 + 4, 4)
                if not test or test != "\x40\x00\x00\x00":
                    continue

                htable = obj.Object("_bash_hash_table", offset = ptr2, vm = proc_as)
                
                for ent in htable:
                    key = str(ent.key.dereference())    
                    val = str(ent.data.dereference_as("_envdata").value.dereference())

                    yield key, val

            bash_was_last = False

    def bash_environment(self):
        proc_as = self.get_process_address_space()
        # In cases when mm is an invalid pointer 
        if not proc_as:
            return

        # Are we dealing with 32 or 64-bit pointers
        if self.obj_vm.profile.metadata.get('memory_model', '32bit') == '32bit':
            pack_format = "<I"
            addr_sz = 4
        else:
            pack_format = "<Q"
            addr_sz = 8

        for key, val in self._dynamic_env(proc_as, pack_format, addr_sz):
            yield key, val        

        for key, val in self._shell_variables(proc_as, pack_format, addr_sz):
            yield key, val

    def lsof(self):
        fds = self.files.get_fds()
        max_fds = self.files.get_max_fds()

        fds = obj.Object(theType = 'Array', offset = fds.obj_offset, vm = self.obj_vm, targetType = 'Pointer', count = max_fds)

        # mem corruption check
        if max_fds > 500000:
            return 

        for i in range(max_fds):
            if fds[i]:
                filp = obj.Object('file', offset = fds[i], vm = self.obj_vm)
                yield filp, i

    # has to get the struct socket given an inode (see SOCKET_I in sock.h)
    def SOCKET_I(self, inode):
        # if too many of these, write a container_of
        backsize = self.obj_vm.profile.get_obj_size("socket")
        addr = inode - backsize

        return obj.Object('socket', offset = addr, vm = self.obj_vm)

    def netstat(self):
        sfop = self.obj_vm.profile.get_symbol("socket_file_ops")
        dfop = self.obj_vm.profile.get_symbol("sockfs_dentry_operations")
        
        for (filp, fdnum) in self.lsof(): 
            if filp.f_op == sfop or filp.dentry.d_op == dfop:
                iaddr = filp.dentry.d_inode
                skt = self.SOCKET_I(iaddr)
                inet_sock = obj.Object("inet_sock", offset = skt.sk, vm = self.obj_vm)

                if inet_sock.protocol in ("TCP", "UDP", "IP", "HOPOPT"): #hopopt is where unix sockets end up on linux
                    state = inet_sock.state if inet_sock.protocol == "TCP" else ""
                    family = inet_sock.sk.__sk_common.skc_family #pylint: disable-msg=W0212

                    if family == 1: # AF_UNIX
                        unix_sock = obj.Object("unix_sock", offset = inet_sock.sk.v(), vm = self.obj_vm)

                        if unix_sock.addr:
                            name_obj = obj.Object("sockaddr_un", offset = unix_sock.addr.name.obj_offset, vm = self.obj_vm)
                            name   = str(name_obj.sun_path)
                        else:
                            name = ""

                        yield (1, (name, iaddr.i_ino))

                    elif family in (socket.AF_INET, socket.AF_INET6, 10, 30):
                        sport = inet_sock.src_port 
                        dport = inet_sock.dst_port 
                        saddr = inet_sock.src_addr
                        daddr = inet_sock.dst_addr

                        yield (socket.AF_INET, (inet_sock, inet_sock.protocol, saddr, sport, daddr, dport, state)) 

    def get_process_address_space(self):
        ## If we've got a NoneObject, return it maintain the reason
        if not self.mm:
            return self.mm

        if self.mm.pgd.v() == None:
            return self.mm.pgd.v()

        directory_table_base = self.obj_vm.vtop(self.mm.pgd.v())

        try:
            process_as = self.obj_vm.__class__(
                self.obj_vm.base, self.obj_vm.get_config(), dtb = directory_table_base)

        except AssertionError, _e:
            return obj.NoneObject("Unable to get process AS")

        process_as.name = "Process {0}".format(self.pid)

        return process_as

    def get_libdl_maps(self):
        proc_as = self.get_process_address_space()
        if proc_as == None:
            return       
 
        found_list = False

        for vma in self.get_proc_maps():
            # find the executable part of libdl
            ehdr = obj.Object("elf_hdr", offset = vma.vm_start, vm = proc_as)

            if not ehdr or not ehdr.is_valid():
                continue

            for phdr in ehdr.program_headers():
                if str(phdr.p_type) != 'PT_DYNAMIC':
                    continue

                for dsec in phdr.dynamic_sections():
                    # link_map is stored at the second GOT entry
                    if dsec.d_tag == 3: # DT_PLTGOT
                        seen_ents = {}
                        got_start = dsec.d_ptr
                        # size_cache tells us if we are a 32 or 64 bit ELF file
                        link_map_addr = obj.Object("Pointer", offset = got_start + (dsec.size_cache / 8), vm = proc_as)
                        link_map = obj.Object("elf_link_map", offset = link_map_addr, vm = proc_as, parent = dsec)
                        for ent in link_map:
                            if ent.obj_offset in seen_ents:
                                continue
                            found_list = True
                            yield ent
                            seen_ents[ent.obj_offset] = 1

            if found_list:
                break

    def threads(self):
        thread_offset = self.obj_vm.profile.get_obj_offset("task_struct", "thread_group")
        threads = [self]
        x = obj.Object('task_struct', self.thread_group.next.v() - thread_offset, self.obj_vm)
        while x not in threads and x.is_valid() and x.thread_group.is_valid() and x.thread_group.next.is_valid():
            threads.append(x)
            x = obj.Object('task_struct', x.thread_group.next.v() - thread_offset, self.obj_vm)
        return threads

    def get_proc_maps(self):
        if not self.mm:
            return
        seen = {}
        for vma in linux_common.walk_internal_list("vm_area_struct", "vm_next", self.mm.mmap):
            val = vma.v()
            if val in seen:
                break

            yield vma

            seen[val] = 1
   
    def _walk_rb(self, rb):
        if not rb.is_valid():
             return

        # container_of
        rboff = self.obj_vm.profile.get_obj_offset("vm_area_struct", "vm_rb")
        vma = obj.Object("vm_area_struct", offset = rb - rboff, vm = self.obj_vm)

        yield vma

        for vma in self._walk_rb(rb.rb_left):
            yield vma
 
        for vma in self._walk_rb(rb.rb_right):
            yield vma

    # based on find_vma in mm/mmap.c 
    def get_proc_maps_rb(self):
        vmas = {}
        rb = self.mm.mm_rb.rb_node

        for vma in self._walk_rb(rb):
            vmas[vma.vm_start] = vma
 
        for key in sorted(vmas.iterkeys()):
            yield vmas[key]

    def search_process_memory(self, s, heap_only = False):

        # Allow for some overlap in case objects are 
        # right on page boundaries 
        overlap = 1024
        
        # Make sure s in a list. This allows you to search for
        # multiple strings at once, without changing the API.
        if type(s) != list:
            debug.warning("Single strings to search_process_memory is deprecated, use a list instead")
            s = [s]

        scan_blk_sz = 1024 * 1024 * 10

        addr_space = self.get_process_address_space()
        if addr_space == None:
            return

        for vma in self.get_proc_maps():
            if heap_only:
                if not (vma.vm_start <= self.mm.start_brk and vma.vm_end >= self.mm.brk):
                    continue

            offset = vma.vm_start
            out_of_range = vma.vm_start + (vma.vm_end - vma.vm_start)
            while offset < out_of_range:
                # Read some data and match it.
                to_read = min(scan_blk_sz + overlap, out_of_range - offset)
                data = addr_space.zread(offset, to_read)
                if not data:
                    break
                for x in s:
                    for hit in utils.iterfind(data, x):
                        yield offset + hit
                offset += min(to_read, scan_blk_sz)

    def elfs(self):
        proc_as = self.get_process_address_space()
        if proc_as == None:
            return

        for vma in self.get_proc_maps():
            elf = obj.Object("elf_hdr", offset = vma.vm_start, vm = proc_as) 

            if not elf.is_valid():
                continue

            pt_loads = []
            dt_soname = None
            dt_strtab = None
            dt_needed = []
             
            #### Walk pt_load and gather ranges
            for phdr in elf.program_headers():
                if not phdr.is_valid():
                    continue                         
               
                if str(phdr.p_type) == 'PT_LOAD':
                    pt_loads.append((phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz))

                if str(phdr.p_type) != 'PT_DYNAMIC':
                    continue                   
             
                for dsec in phdr.dynamic_sections():
                    if dsec.d_tag == 5:
                        dt_strtab = dsec.d_ptr

                    elif dsec.d_tag == 14:
                        dt_soname = dsec.d_ptr

                    elif dsec.d_tag == 1:
                        dt_needed.append(dsec.d_ptr)
           
                break
                 
            if dt_strtab == None or dt_needed == []:
                continue

            needed = []
            for n_idx in dt_needed:
                buf = proc_as.read(dt_strtab + n_idx, 256)
                if buf:
                    idx = buf.find("\x00")
                    if idx != -1:
                        buf = buf[:idx]

                    if len(buf) > 0:
                        needed.append(buf)
            
            soname = ""     
            if dt_soname:
                soname = proc_as.read(dt_strtab + dt_soname, 256)
                if soname:
                    idx = soname.find("\x00")
                    if idx != -1:
                        soname = soname[:idx]
            
            if not soname or len(soname) == 0:
                soname = linux_common.get_path(self, vma.vm_file)

            if pt_loads: 
                (elf_start, elf_end) = (min(s[0] for s in pt_loads), max(s[1] for s in pt_loads))
            else:
                continue

            # TODO - test diff without setting soname of vma
            if soname or needed:
                yield elf, elf_start, elf_end, soname, needed

    def ACTHZ(self, CLOCK_TICK_RATE, HZ):
        LATCH = ((CLOCK_TICK_RATE + HZ/2) / HZ)
        return self.SH_DIV(CLOCK_TICK_RATE, LATCH, 8)

    def SH_DIV(self, NOM, DEN, LSH):
        return ((NOM / DEN) << LSH) + (((NOM % DEN) << LSH) + DEN / 2) / DEN

    def TICK_NSEC(self):
        HZ = 1000
        CLOCK_TICK_RATE = 1193182 

        return self.SH_DIV(1000000 * 1000, self.ACTHZ(CLOCK_TICK_RATE, HZ), 8)

    def get_time_vars(self):
        '''
        Sometime in 3.[3-5], Linux switched to a global timekeeper structure
        This just figures out which is in use and returns the correct variables
        '''

        wall_addr       = self.obj_vm.profile.get_symbol("wall_to_monotonic")
        sleep_addr      = self.obj_vm.profile.get_symbol("total_sleep_time")
        timekeeper_addr = self.obj_vm.profile.get_symbol("timekeeper")
        tkcore_addr     = self.obj_vm.profile.get_symbol("tk_core") 

        # old way
        if wall_addr and sleep_addr:
            wall = obj.Object("timespec", offset = wall_addr, vm = self.obj_vm)
            timeo = obj.Object("timespec", offset = sleep_addr, vm = self.obj_vm)

        elif wall_addr:
            wall  = obj.Object("timespec", offset = wall_addr, vm = self.obj_vm)
            timeo = linux_common.vol_timespec(0, 0)
    
        # timekeeper way
        elif timekeeper_addr:
            timekeeper = obj.Object("timekeeper", offset = timekeeper_addr, vm = self.obj_vm)
            wall = timekeeper.wall_to_monotonic
            timeo = timekeeper.total_sleep_time

        # 3.17(ish) - 3.19(ish) way
        elif tkcore_addr and hasattr("timekeeper", "total_sleep_time"):
            # skip seqcount
            timekeeper = obj.Object("timekeeper", offset = tkcore_addr + 4, vm = self.obj_vm)
            wall = timekeeper.wall_to_monotonic
            timeo = timekeeper.total_sleep_time

        # 3.19(ish)+
        # getboottime from 3.19.x
        elif tkcore_addr:
            # skip seqcount
            timekeeper = obj.Object("timekeeper", offset = tkcore_addr + 8, vm = self.obj_vm)
            wall = timekeeper.wall_to_monotonic

            oreal = timekeeper.offs_real
            oboot = timekeeper.offs_boot
 
            tv64 = (oreal.tv64 & 0xffffffff) - (oboot.tv64 & 0xffffffff)

            if tv64:
                tv64 = (tv64 / 100000000) * -1
                timeo = linux_common.vol_timespec(tv64, 0) 
            else:
                timeo = None

        return (wall, timeo)

    # based on 2.6.35 getboottime
    def get_boot_time(self):
        (wall, timeo) = self.get_time_vars()

        if wall == None or timeo == None:
            return -1

        secs = wall.tv_sec + timeo.tv_sec
        nsecs = wall.tv_nsec + timeo.tv_nsec

        secs = secs * -1
        nsecs = nsecs * -1

        while nsecs >= linux_common.nsecs_per:
            nsecs = nsecs - linux_common.nsecs_per
            secs = secs + 1

        while nsecs < 0:
            nsecs = nsecs + linux_common.nsecs_per
            secs = secs - 1

        boot_time = secs + (nsecs / linux_common.nsecs_per / 100)

        return boot_time
        
    def get_task_start_time(self):
        if hasattr(self, "real_start_time"):
            start_time = self.real_start_time
        else:
            start_time = self.start_time

        if type(start_time) == volatility.obj.NativeType and type(start_time.v()) == long:
            start_time = linux_common.vol_timespec(start_time.v() / 0x989680 / 100, 0)

        start_secs = start_time.tv_sec + (start_time.tv_nsec / linux_common.nsecs_per / 100)

        boot_time =  self.get_boot_time()
       
        if boot_time != -1:
            sec = boot_time + start_secs

            # convert the integer as little endian 
            try:
                data = struct.pack("<I", sec)
            except struct.error, e:
                # in case we exceed 0 <= number <= 4294967295
                return 0

            bufferas = addrspace.BufferAddressSpace(self.obj_vm.get_config(), data = data)
            dt = obj.Object("UnixTimeStamp", offset = 0, vm = bufferas, is_utc = True)
        else:
            dt = None
        
        return dt

    def get_environment(self):
        if self.mm:
            # set the as with our new dtb so we can read from userland
            proc_as = self.get_process_address_space()
            if proc_as == None:
                return ""

            # read argv from userland
            start = self.mm.env_start.v()

            argv = proc_as.read(start, self.mm.env_end - self.mm.env_start + 10)
            
            if argv:
                # split the \x00 buffer into args
                env = " ".join(argv.split("\x00"))

            else:
                env = ""
        else:
            # kernel thread
            env = ""

        if len(env) > 1 and env[-1] == " ":
            env = env[:-1]

        return env

    def get_commandline(self):
        if self.mm:
            # set the as with our new dtb so we can read from userland
            proc_as = self.get_process_address_space()
            if proc_as == None:
                return ""

            # read argv from userland
            start = self.mm.arg_start.v()

            argv = proc_as.read(start, self.mm.arg_end - self.mm.arg_start)

            if argv:
                # split the \x00 buffer into args
                name = " ".join(argv.split("\x00"))
            else:
                name = ""
        else:
            # kernel thread
            name = "[" + self.comm + "]"
    
        if len(name) > 1 and name[-1] == " ":
            name = name[:-1]

        return name

class linux_fs_struct(obj.CType):

    def get_root_dentry(self):
        # < 2.6.26
        if hasattr(self, "rootmnt"):
            ret = self.root
        else:
            ret = self.root.dentry

        return ret

    def get_root_mnt(self):
        # < 2.6.26
        if hasattr(self, "rootmnt"):
            ret = self.rootmnt
        else:
            ret = self.root.mnt

        return ret

    def get_pwd_dentry(self):
        # < 2.6.26
        if hasattr(self, "pwdmnt"):
            ret = self.pwd
        else:
            ret = self.pwd.dentry

        return ret

    def get_pwd_mnt(self):
        # < 2.6.26
        if hasattr(self, "pwdmnt"):
            ret = self.pwdmnt
        else:
            ret = self.pwd.mnt

        return ret

class super_block(obj.CType):

    @property
    def major(self):
        return self.s_dev >> 20
        
    @property
    def minor(self):
        return self.s_dev & ((1 << 20) - 1)

class inode(obj.CType):

    def is_dir(self):
        """Mimic the S_ISDIR macro"""
        return self.i_mode & linux_flags.S_IFMT == linux_flags.S_IFDIR
    
    def is_reg(self):
        """Mimic the S_ISREG macro"""
        return self.i_mode & linux_flags.S_IFMT == linux_flags.S_IFREG

class timespec(obj.CType):

    def as_timestamp(self):
        time_val = struct.pack("<I", self.tv_sec)
        time_buf = addrspace.BufferAddressSpace(self.obj_vm.get_config(), data = time_val)
        time_obj = obj.Object("UnixTimeStamp", offset = 0, vm = time_buf, is_utc = True)
        
        return time_obj

class dentry(obj.CType):
    def get_partial_path(self):
        """ we can't get the full path b/c we 
        do not have a ref to the vfsmnt """

        path = []
        name = ""
        dentry = self
    
        while dentry and dentry != dentry.d_parent:
            name = dentry.d_name.name.dereference_as("String", length = 255)
            if name.is_valid():
                path.append(str(name))
            dentry = dentry.d_parent
    
        path.reverse()
        str_path = "/".join([p for p in path])
        return str_path

    @property
    def d_count(self):
        ret = self.members.get("d_count")
        if ret is None:
            ret = self.d_lockref.count
        else:
            ret = self.m("d_count")
        return ret

class swapperScan(scan.BaseScanner):
    """ Scanner for swapper string for Mountain Lion """
    checks = []

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles}) ]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def generate_suggestions(self):
        """Tries to locate the DTB."""
        profile = self.obj_vm.profile
        
        if profile.metadata.get('memory_model', '32bit') == "32bit":
            sym   = "swapper_pg_dir"
            shifts = [0xc0000000]
        else:
            sym   = "init_level4_pgt"
            shifts = [0xffffffff80000000, 0xffffffff80000000 - 0x1000000, 0xffffffff7fe00000]       
        
        config         = self.obj_vm.get_config()
        tbl = self.obj_vm.profile.sys_map["kernel"]
        
        if config.SHIFT:
            shift_address = config.SHIFT
        else:
            shift_address = self.obj_vm.profile.shift_address

        good_dtb = -1
            
        init_task_addr = tbl["init_task"][0][0] + shift_address
        dtb_sym_addr   = tbl[sym][0][0] + shift_address
        
        comm_offset    = profile.get_obj_offset("task_struct", "comm")
        pid_offset     = self.obj_vm.profile.get_obj_offset("task_struct", "pid")
        pas            = self.obj_vm
        
        for shift in shifts:
            sym_addr = dtb_sym_addr - shift
       
            read_addr = init_task_addr - shift + comm_offset

            buf = pas.read(read_addr, 12)        
          
            if buf:
                idx = buf.find("swapper")
                if idx == 0:
                    good_dtb = sym_addr
                    break

        # check for relocated kernel
        if good_dtb == -1 and shift_address == 0:
            scanner = swapperScan(needles = ["swapper/0\x00\x00\x00\x00\x00\x00"])
            for swapper_offset in scanner.scan(self.obj_vm):
                swapper_address = swapper_offset - comm_offset

                if pas.read(swapper_address, 4) != "\x00\x00\x00\x00":
                    continue

                if pas.read(swapper_address + pid_offset, 4) != "\x00\x00\x00\x00":
                    continue

                tmp_shift_address = swapper_address - (init_task_addr - shifts[0])

                if tmp_shift_address & 0xfff != 0x000:
                    continue
                
                shift_address = tmp_shift_address
                good_dtb = dtb_sym_addr - shifts[0] + shift_address
                break

        if shift_address != 0:   
            self.obj_vm.profile.shift_address = shift_address

        yield good_dtb

# the intel check, simply checks for the static paging of init_task
class VolatilityLinuxIntelValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid Arm Paged space"""

    def generate_suggestions(self):

        init_task_addr = self.obj_vm.profile.get_symbol("init_task")

        if self.obj_vm.profile.metadata.get('memory_model', '32bit') == "32bit":
            shifts = [0xc0000000]
        else:
            shifts = [0xffffffff80000000, 0xffffffff80000000 - 0x1000000, 0xffffffff7fe00000]       

        ret = False

        for shift in shifts:
            phys  = self.obj_vm.vtop(init_task_addr)
            check = init_task_addr - shift
           
            if phys == check:
                ret = True
                break

        yield ret

# the ARM check, has to check multiple values b/c phones do not map RAM at 0
class VolatilityLinuxARMValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid Arm Paged space"""
    def generate_suggestions(self):

        init_task_addr = self.obj_vm.profile.get_symbol("init_task")
        do_fork_addr   = self.obj_vm.profile.get_symbol("do_fork") 

        if not do_fork_addr or not init_task_addr:
            return

        sym_addr_diff = (do_fork_addr - init_task_addr)

        if self.obj_vm.profile.metadata.get('memory_model', '32bit') == "32bit":
            shift = 0xc0000000
        else:
            shift = 0xffffffff80000000
            
        task_paddr = self.obj_vm.vtop(init_task_addr)
        fork_paddr = self.obj_vm.vtop(do_fork_addr)

        if task_paddr and fork_paddr:
            # these won't be zero due to RAM not at physical address 0
            # but if the offset from 0 is the same across two paging operations
            # then we have the right DTB
            task_off = task_paddr - shift
            fork_off = fork_paddr - shift

            yield fork_off - task_off == sym_addr_diff

class LinuxObjectClasses(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.object_classes.update({
            'fs_struct': linux_fs_struct,
            'file': linux_file,
            'list_head': list_head,
            'hlist_node': hlist_node,
            'files_struct': files_struct,
            'task_struct': task_struct,
            'vm_area_struct': vm_area_struct,
            'module' : module_struct,
            'hlist_bl_node' : hlist_bl_node,
            'net_device' : net_device,
            'in_device'  : in_device,
            'tty_ldisc' : tty_ldisc,
            'module_sect_attr' : module_sect_attr,
            'VolatilityDTB': VolatilityDTB,
            'IpAddress': basic.IpAddress,
            'Ipv6Address': basic.Ipv6Address,
            'VolatilityLinuxIntelValidAS' : VolatilityLinuxIntelValidAS,
            'VolatilityLinuxARMValidAS' : VolatilityLinuxARMValidAS,
            'kernel_param' : kernel_param,
            'kparam_array' : kparam_array,
            'desc_struct' : desc_struct,
            'page': page,
            'LinuxPermissionFlags': LinuxPermissionFlags,
            'super_block' : super_block, 
            'inode' : inode,
            'dentry' : dentry,
            'timespec' : timespec,
            'sock' : sock,
            'inet_sock' : inet_sock,
            })

class LinuxOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses'] # , 'LinuxVTypes']

    def modification(self, profile):
        profile.merge_overlay(linux_overlay)

class LinuxIntelOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux',
                  'arch' : lambda x: x == 'x86' or x == 'x64'}
    before = ['BasicObjectClasses'] # , 'LinuxVTypes']

    def modification(self, profile):
        profile.merge_overlay(intel_overlay)

class page(obj.CType):

    def to_vaddr(self):
        #FIXME Do it!
        pass

    def to_paddr(self):
        mem_map_addr = self.obj_vm.profile.get_symbol("mem_map")
        mem_section_addr = self.obj_vm.profile.get_symbol("mem_section")

        if mem_map_addr:
            # FLATMEM kernels, usually 32 bit
            mem_map_ptr = obj.Object("Pointer", offset = mem_map_addr, vm = self.obj_vm, parent = self.obj_parent)

        elif mem_section_addr:
            # this is hardcoded in the kernel - VMEMMAPSTART, usually 64 bit kernels
            mem_map_ptr = 0xffffea0000000000

        else:
            debug.error("phys_addr_of_page: Unable to determine physical address of page. NUMA is not supported at this time.\n")

        phys_offset = (self.obj_offset - mem_map_ptr) / self.obj_vm.profile.get_obj_size("page")

        phys_offset = phys_offset << 12

        return phys_offset

class mount(obj.CType):
    @property
    def mnt_sb(self):

        if hasattr(self, "mnt"):
            ret = self.mnt.mnt_sb
        else:
            ret = self.mnt_sb

        return ret

    @property
    def mnt_root(self):

        if hasattr(self, "mnt"):
            ret = self.mnt.mnt_root
        else:
            ret = self.mnt_root

        return ret

    @property
    def mnt_flags(self):

        if hasattr(self, "mnt"):
            ret = self.mnt.mnt_flags
        else:
            ret = self.mnt_flags

        return ret

class vfsmount(obj.CType):
    def is_valid(self):
        return self.mnt_sb.is_valid() and \
               self.mnt_root.is_valid() and \
               self.mnt_parent.is_valid()

    def _get_real_mnt(self):

        offset = self.obj_vm.profile.get_obj_offset("mount", "mnt")
        mnt = obj.Object("mount", offset = self.obj_offset - offset, vm = self.obj_vm)
        return mnt

    @property
    def mnt_parent(self):

        ret = self.members.get("mnt_parent")
        if ret is None:
            ret = self._get_real_mnt().mnt_parent
        else:
            ret = self.m("mnt_parent")
        return ret

    @property
    def mnt_mountpoint(self):

        ret = self.members.get("mnt_mountpoint")
        if ret is None:
            ret = self._get_real_mnt().mnt_mountpoint
        else:
            ret = self.m("mnt_mountpoint")
        return ret

class LinuxMountOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses'] # , 'LinuxVTypes']

    def modification(self, profile):

        if profile.vtypes.get("mount"):
            profile.object_classes.update({'mount' : mount, 'vfsmount' : vfsmount})
        else:
            profile.object_classes.update({'vfsmount' : vfsmount})

class LinuxGate64Overlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses'] # , 'LinuxVTypes']

    def modification(self, profile):
        if profile.has_type("gate_struct64"): 
            profile.object_classes.update({'gate_struct64' : gate_struct64})





