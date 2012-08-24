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
import volatility.obj as obj
import volatility.debug as debug
import volatility.dwarf as dwarf

x64_native_types = copy.deepcopy(native_types.x64_native_types)

x64_native_types['long'] = [8, '<q']
x64_native_types['unsigned long'] = [8, '<Q']

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
    'dentry' : [None, {
        'd_u'      : [ None , ['list_head', {}]],
    }],
    'cpuinfo_x86' : [None, {
        'x86_model_id'  : [ None , ['String', dict(length = 64)]],
        'x86_vendor_id' : [ None, ['String', dict(length = 16)]],
        }],
    'VOLATILITY_MAGIC': [None, {
        'DTB'           : [ 0x0, ['VolatilityDTB', dict(configname = "DTB")]],
        'ArmValidAS'   :  [ 0x0, ['VolatilityArmValidAS']],
        }],
    }

def parse_system_map(data, module):
    """Parse the symbol file."""
    sys_map         = {}
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

    vtypesvar = {}
    sysmapvar = {}

    memmodel, arch = "32bit", "x86"
    profilename = os.path.splitext(os.path.basename(profpkg.filename))[0]

    for f in profpkg.filelist:
        if f.filename.lower().endswith('.dwarf'):
            data = profpkg.read(f.filename)
            vtypesvar.update(dwarf.DWARFParser(data).finalize())
            debug.debug("{2}: Found dwarf file {0} with {1} symbols".format(f.filename, len(vtypesvar.keys()), profilename))
        elif 'system.map' in f.filename.lower():
            memmodel, sysmap = parse_system_map(profpkg.read(f.filename), "kernel")
            if memmodel == "64bit":
                arch = "x64"
            sysmapvar.update(sysmap)
            debug.debug("{2}: Found system file {0} with {1} symbols".format(f.filename, len(sysmapvar.keys()), profilename))

    if not sysmapvar or not vtypesvar:
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
            self.sy_smap = {}
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
    def list_of_type(self, type, member, offset = -1, forward = True, head_sentinel = True):
        
        if not self.is_valid():
            return

        ## Get the first element
        if forward:
            nxt = self.next.dereference()
        else:
            nxt = self.pprev.dereference().dereference()

        offset = self.obj_vm.profile.get_obj_offset(type, member)

        seen = set()
        if head_sentinel:
            # We're a header element and not to be included in the list
            seen.add(self.obj_offset)

        while nxt.is_valid() and nxt.obj_offset not in seen:
            ## Instantiate the object
            item = obj.Object(type, offset = nxt.obj_offset - offset,
                                    vm = self.obj_vm,
                                    parent = self.obj_parent,
                                    name = type)

            seen.add(nxt.obj_offset)

            yield item

            if forward:
                nxt = item.m(member).next.dereference()
            else:
                nxt = item.m(member).pprev.dereference().dereference()


    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.next) or bool(self.prev)

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_name, self.obj_name)


class list_head(obj.CType):
    """A list_head makes a doubly linked list."""
    def list_of_type(self, type, member, offset = -1, forward = True, head_sentinel = True):
        if not self.is_valid():
            return

        ## Get the first element
        if forward:
            nxt = self.next.dereference()
        else:
            nxt = self.prev.dereference()

        offset = self.obj_vm.profile.get_obj_offset(type, member)

        seen = set()
        if head_sentinel:
            # We're a header element and not to be included in the list
            seen.add(self.obj_offset)

        while nxt.is_valid() and nxt.obj_offset not in seen:
            ## Instantiate the object
            item = obj.Object(type, offset = nxt.obj_offset - offset,
                                    vm = self.obj_vm,
                                    parent = self.obj_parent,
                                    name = type)

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

class task_struct(obj.CType):

    @property
    def uid(self):
        ret = self.members.get("uid")
        if ret is None:
            ret = self.cred.uid

        return ret

    @property
    def gid(self):
        ret = self.members.get("gid")
        if ret is None:
            ret = self.cred.gid

        return ret

    @property
    def euid(self):
        ret = self.members.get("euid")
        if ret is None:
            ret = self.cred.euid

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

class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def generate_suggestions(self):
        """Tries to locate the DTB."""
        profile = self.obj_vm.profile

        if self.obj_vm.profile.metadata.get('memory_model', '32bit') == "32bit":
            shift = 0xc0000000
        else:
            shift = 0xffffffff80000000

        # this is the only code allowed to reference the internal sys_map!
        yield profile.sys_map["kernel"]["swapper_pg_dir"][0][0] - shift

class VolatilityArmValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid Arm Paged space"""

    def generate_suggestions(self):

        # linux has a virtual to physical offset (minux 0xc0000000) for kernel addresses
        # we simply .vtop an address that will be in the kernel and see if we get the correct address back
        # will add 64 bit support if/when ARM ever releases 64 bit chips ;)
        #val = self.obj_vm.vtop(0xc0315760)
        val = self.obj_vm.vtop(0xc0548cf8)

        #if val == 0x315760:
        #if val and val & 0x548cf8 == 0x548cf8: 
        yield (val > 0)

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
            'VolatilityDTB': VolatilityDTB,
            'IpAddress': basic.IpAddress,
            'Ipv6Address': basic.Ipv6Address,
            'VolatilityArmValidAS' : VolatilityArmValidAS,
            })

class LinuxOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses'] # , 'LinuxVTypes']

    def modification(self, profile):
        profile.merge_overlay(linux_overlay)
