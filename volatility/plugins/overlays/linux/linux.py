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

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      brendandg@gatech.edu
@organization: Georgia Institute of Technology
"""

import os
import copy
import zipfile

import volatility.plugins
import volatility.plugins.overlays.basic as basic
import volatility.plugins.overlays.native_types as native_types
import volatility.exceptions as exceptions
import volatility.obj as obj
import volatility.debug as debug
import volatility.dwarf as dwarf
import volatility.plugins.linux.common as linux_common

x64_native_types = copy.deepcopy(native_types.x64_native_types)

x64_native_types['long'] = [8, '<q']
x64_native_types['unsigned long'] = [8, '<Q']

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

linux_overlay = {
    'task_struct' : [None, {
        'comm'          : [ None , ['String', dict(length = 16)]],
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
    'cpuinfo_x86' : [None, {
        'x86_model_id'  : [ None , ['String', dict(length = 64)]],
        'x86_vendor_id' : [ None, ['String', dict(length = 16)]],
        }],
    'VOLATILITY_MAGIC': [None, {
        'DTB'           : [ 0x0, ['VolatilityDTB', dict(configname = "DTB")]],
        'ArmValidAS'   :  [ 0x0, ['VolatilityLinuxARMValidAS']],
        'IA32ValidAS'  :  [ 0x0, ['VolatilityLinuxIntelValidAS']],
        'AMD64ValidAS'  :  [ 0x0, ['VolatilityLinuxIntelValidAS']],
        }],
    'vm_area_struct' : [ None, { 
        'vm_flags' : [ None, ['LinuxPermissionFlags', {'bitmap': {'r': 0, 'w': 1, 'x': 2}}]],
        }],
    }

def parse_system_map(data, module):
    """Parse the symbol file."""
    sys_map = {}
    sys_map[module] = {}

    arch = None

    # get the system map
    for line in data.splitlines():
        (str_addr, symbol_type, symbol) = line.strip().split()

        try:
            sym_addr = long(str_addr, 16)

        except ValueError:
            continue

        if not symbol in sys_map[module]:
            sys_map[module][symbol] = []

        sys_map[module][symbol].append([sym_addr, symbol_type])

    arch = str(len(str_addr) * 4) + "bit"

    return arch, sys_map

def LinuxProfileFactory(profpkg):
    """ Takes in a zip file, spits out a LinuxProfile class

        The zipfile should include at least one .dwarf file
        and the appropriate system.map file.

        To generate a suitable dwarf file:
        dwarfdump -di vmlinux > output.dwarf
    """

    dwarfdata = None
    sysmapdata = None

    memmodel, arch = "32bit", "x86"
    profilename = os.path.splitext(os.path.basename(profpkg.filename))[0]

    for f in profpkg.filelist:
        if f.filename.lower().endswith('.dwarf'):
            dwarfdata = profpkg.read(f.filename)
        elif 'system.map' in f.filename.lower():
            sysmapdata = profpkg.read(f.filename)
            (address, _a, _b) = sysmapdata.splitlines()[0].strip().split()
            memmodel = str(len(address) * 4) + "bit"

    if memmodel == "64bit":
        arch = "x64"

    if not sysmapdata or not dwarfdata:
        # Might be worth throwing an exception here?
        return None

    class AbstractLinuxProfile(obj.Profile):
        __doc__ = "A Profile for Linux " + profilename + " " + arch
        _md_os = "linux"
        _md_memory_model = memmodel
        # Override 64-bit native_types
        native_mapping = {'32bit': native_types.x86_native_types,
                          '64bit': x64_native_types}

        def __init__(self, *args, **kwargs):
            # change the name to catch any code referencing the old hash table
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
            _memmodel, sysmapvar = parse_system_map(sysmapdata, "kernel")
            debug.debug("{2}: Found system file {0} with {1} symbols".format(f.filename, len(sysmapvar.keys()), profilename))

            self.sys_map.update(sysmapvar)

        def get_all_symbols(self, module = "kernel"):
            """ Gets all the symbol tuples for the given module """

            ret = []

            symtable = self.sys_map

            if module in symtable:

                mod = symtable[module]

                for (name, addrs) in mod.items():
                    ret.append(addrs)
            else:
                debug.info("All symbols requested for non-existent module %s" % module)

            return ret

        def get_all_addresses(self, module = "kernel"):
            """ Gets all the symbol addresses for the given module """

            # returns a hash table for quick looks
            # the main use of this function is to see if an address is known
            ret = {}

            symbols = self.get_all_symbols(module)

            for sym in symbols:

                for (addr, addrtype) in sym:
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
            nxt = self.next.dereference()
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
                nxt = item.m(member).next.dereference()
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
            # FIXME: change in 2.3 when truncation no longer occurs
            seen.add(self.obj_offset & 0xffffffffffff)

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

        low = self.offset_low
        middle = self.offset_middle
        high = self.offset_high

        ret = (high << 32) | (middle << 16) | low

        return ret

class desc_struct(obj.CType):

    @property
    def Address(self):

        return (self.b & 0xffff0000) | (self.a & 0x0000ffff)

class module_sect_attr(obj.CType):
        
    def get_name(self):
        
        if type(self.m("name")) == obj.Array:
            name = obj.Object("String", offset = self.m("name").obj_offset, vm = self.obj_vm, length = 32)
        else:
            name = self.name.dereference_as("String", length = 255)

        return name         

class task_struct(obj.CType):
    def is_valid_task(self):

        ret = self.fs.v() != 0 and self.files.v() != 0

        if ret and self.members.get("cred"):
            ret = self.cred.is_valid()

        return ret

    @property
    def uid(self):
        ret = self.members.get("uid")
        if ret is None:
            ret = self.cred.uid
        else:
            ret = self.m("uid")

        return ret

    @property
    def gid(self):
        ret = self.members.get("gid")
        if ret is None:
            gid = self.cred.gid
            if hasattr(gid, 'counter'):
                ret = obj.Object("int", offset = gid.v(), vm = self.obj_vm)
            else:
                ret = gid
        else:
            ret = self.m("gid")

        return ret

    @property
    def euid(self):
        ret = self.members.get("euid")
        if ret is None:
            ret = self.cred.euid
        else:
            ret = self.m("euid")

        return ret

    def get_process_address_space(self):
        ## If we've got a NoneObject, return it maintain the reason
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

    def get_proc_maps(self):
        for vma in linux_common.walk_internal_list("vm_area_struct", "vm_next", self.mm.mmap):
            yield vma
    
    def search_process_memory(self, s):
        def iterfind(data, string):
            offset = data.find(string, 0)
            while offset >= 0:
                yield offset
                offset = data.find(string, offset + len(string))

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

        for vma in self.get_proc_maps():
            offset = vma.vm_start
            out_of_range = vma.vm_start + (vma.vm_end - vma.vm_start)
            while offset < out_of_range:
                # Read some data and match it.
                to_read = min(scan_blk_sz + overlap, out_of_range - offset)
                data = addr_space.zread(offset, to_read)
                if not data:
                    break
                for x in s:
                    for hit in iterfind(data, x):
                        yield offset + hit
                offset += min(to_read, scan_blk_sz)

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

class net_device(obj.CType):

    @property
    def promisc(self):
        return self.flags & 0x100 == 0x100 # IFF_PROMISC

class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def generate_suggestions(self):
        """Tries to locate the DTB."""
        shift = 0xc0000000
        # this is the only code allowed to reference the internal sys_map!
        yield self.obj_vm.profile.get_symbol("swapper_pg_dir") - shift

# the intel check, simply checks for the static paging of init_task
class VolatilityLinuxIntelValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid Arm Paged space"""

    def generate_suggestions(self):

        init_task_addr = self.obj_vm.profile.get_symbol("init_task")

        if self.obj_vm.profile.metadata.get('memory_model', '32bit') == "32bit":
            shift = 0xc0000000
        else:
            shift = 0xffffffff80000000

        yield self.obj_vm.vtop(init_task_addr) == init_task_addr - shift

# the ARM check, has to check multiple values b/c phones do not map RAM at 0
class VolatilityLinuxARMValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid Arm Paged space"""
    def generate_suggestions(self):

        init_task_addr = self.obj_vm.profile.get_symbol("init_task")
        do_fork_addr   = self.obj_vm.profile.get_symbol("do_fork") 

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
            'module_sect_attr' : module_sect_attr,
            'VolatilityDTB': VolatilityDTB,
            'IpAddress': basic.IpAddress,
            'Ipv6Address': basic.Ipv6Address,
            'VolatilityLinuxIntelValidAS' : VolatilityLinuxIntelValidAS,
            'VolatilityLinuxARMValidAS' : VolatilityLinuxARMValidAS,
            'kernel_param' : kernel_param,
            'kparam_array' : kparam_array,
            'gate_struct64' : gate_struct64,
            'desc_struct' : desc_struct,
            'page': page,
            'net_device': net_device,
            'LinuxPermissionFlags': LinuxPermissionFlags,
            })

class LinuxOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses'] # , 'LinuxVTypes']

    def modification(self, profile):
        profile.merge_overlay(linux_overlay)

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
            # NOTE: This is really 0xffff0xea0000000000 but we chop to its 48 bit equivalent
            mem_map_ptr = 0xea0000000000

        else:
            debug.error("phys_addr_of_page: Unable to determine physical address of page\n")

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


