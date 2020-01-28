# Volatility
# Copyright (C) 2010 Brendan Dolan-Gavitt
# Copyright (c) 2011 Michael Cohen <scudette@gmail.com>
# Copyright (C) 2019 Volatility Foundation
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

import copy
import os
import struct
import zipfile

import volatility.debug as debug
import volatility.exceptions as exceptions
import volatility.dwarf as dwarf
import volatility.obj as obj
import volatility.plugins as plugins
import volatility.plugins.overlays.basic as basic
import volatility.plugins.overlays.native_types as native_types

x64_native_types = copy.deepcopy(native_types.x64_native_types)

x64_native_types['long'] = [8, '<q']
x64_native_types['unsigned long'] = [8, '<Q']

freebsd_overlay = {
    'VOLATILITY_MAGIC' : [ None, {
        'DTB'            : [ 0x0, ['VolatilityDTB', dict(configname = 'DTB')]],
        'IA32ValidAS'    : [ 0x0, ['VolatilityFreebsdValidAS']],
        'AMD64ValidAS'   : [ 0x0, ['VolatilityFreebsdValidAS']],
        }],
    'domain' : [ None, {
        'dom_family' : [ None, ['Enumeration', dict(target = 'int', choices = {
            1: 'AF_UNIX',
            2: 'AF_INET',
            17: 'AF_ROUTE',
            28: 'AF_INET6'})]],
        }],
    'file' : [ None, {
        'f_type' : [ None, ['Enumeration', dict(target = 'short', choices = {
            0: 'DTYPE_NONE',
            1: 'DTYPE_VNODE',
            2: 'DTYPE_SOCKET',
            3: 'DTYPE_PIPE',
            4: 'DTYPE_FIFO',
            5: 'DTYPE_KQUEUE',
            6: 'DTYPE_CRYPTO',
            7: 'DTYPE_MQUEUE',
            8: 'DTYPE_SHM',
            9: 'DTYPE_SEM',
            10: 'DTYPE_PTS',
            11: 'DTYPE_DEV',
            12: 'DTYPE_PROCDESC',
            13: 'DTYPE_LINUXEFD',
            14: 'DTYPE_LINUXTFD'})]],
        }],
    'ifnet' : [ None, {
        'if_dname' : [ None, ['pointer', ['String', dict(length = 1024)]]],
        'if_xname' : [ None, ['String', dict(length = 16)]],
        'if_description' : [ None, ['pointer', ['String', dict(length = 1024)]]],
        }],
    'in_addr' : [ None, {
        's_addr' : [ None, ['IpAddress']],
        }],
    'in6_addr' : [ None, {
        '__u6_addr' : [ None, ['Ipv6Address']],
        }],
    'linker_file' : [ None, {
        'filename' : [ None, ['pointer', ['String', dict(length = 1024)]]],
        'pathname' : [ None, ['pointer', ['String', dict(length = 1024)]]],
        }],
    'module' : [ None, {
        'name' : [ None, ['pointer', ['String', dict(length = 32)]]],
        }],
    'proc' : [ None, {
        'p_comm' : [ None, ['String', dict(length = 20)]],
        }],
    'socket' : [ None, {
        'so_type' : [ None, ['Enumeration', dict(target = 'short', choices = {
            1: 'SOCK_STREAM',
            2: 'SOCK_DGRAM',
            3: 'SOCK_RAW',
            4: 'SOCK_RDM',
            5: 'SOCK_SEQPACKET'})]],
        }],
    'statfs' : [ None, {
        'f_fstypename' : [ None, ['String', dict(length = 16)]],
        'f_mntfromname' : [ None, ['String', dict(length = 1024)]],
        'f_mntonname' : [ None, ['String', dict(length = 1024)]],
        }],
    'vm_object' : [ None, {
        'type' : [ None, ['Enumeration', dict(target = 'unsigned char', choices = {
            0: 'OBJT_DEFAULT',
            1: 'OBJT_SWAP',
            2: 'OBJT_VNODE',
            3: 'OBJT_DEVICE',
            4: 'OBJT_PHYS',
            5: 'OBJT_DEAD',
            6: 'OBJT_SG',
            7: 'OBJT_MGTDEVICE'})]],
        }],
    }

def parse_system_map(data, module):
    """Parse the symbol file."""
    sys_map = {}
    sys_map[module] = {}

    mem_model = None
    arch = 'x86'

    # get the system map
    for line in data.splitlines():
        try:
            (str_addr, symbol_type, symbol) = line.strip().split()
            sym_addr = long(str_addr, 16)

        except ValueError:
            continue

        if symbol == 'KPML4phys':
            arch = 'x64'

        if not symbol in sys_map[module]:
            sys_map[module][symbol] = []

        sys_map[module][symbol].append([sym_addr, symbol_type])

    mem_model = str(len(str_addr) * 4) + 'bit'

    return arch, mem_model, sys_map

def FreebsdProfileFactory(profpkg):
    dwarfdata = None
    sysmapdata = None

    memmodel, arch = '32bit', 'x86'
    profilename = os.path.splitext(os.path.basename(profpkg.filename))[0]

    for f in profpkg.filelist:
        if f.filename.lower().endswith('.dwarf'):
            dwarfdata = profpkg.read(f.filename)
        elif 'freebsd-kernel.map' in f.filename.lower():
            sysmapdata = profpkg.read(f.filename)
            arch, memmodel, sysmap = parse_system_map(profpkg.read(f.filename), 'kernel')

    if not sysmapdata or not dwarfdata:
        return None

    class AbstractFreebsdProfile(obj.Profile):
        __doc__ = 'A Profile for ' + profilename
        _md_os = 'freebsd'
        _md_memory_model = memmodel
        _md_arch = arch
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
                raise exceptions.VolatilityException('Inconsistent freebsd profile - unable to look up ' + str(e))

        def load_vtypes(self):
            """Loads up the vtypes data"""
            ntvar = self.metadata.get('memory_model', '32bit')
            self.native_types = copy.deepcopy(self.native_mapping.get(ntvar))

            vtypesvar = dwarf.DWARFParser(dwarfdata).finalize()
            self._merge_anonymous_members(vtypesvar)
            self.vtypes.update(vtypesvar)
            debug.debug('{2}: Found dwarf file {0} with {1} symbols'.format(f.filename, len(vtypesvar.keys()), profilename))

        def load_sysmap(self):
            """Loads up the system map data"""
            _, _, sysmapvar = parse_system_map(sysmapdata, 'kernel')
            self.sys_map.update(sysmapvar)

        def get_symbol(self, sym_name, nm_type = '', module = 'kernel'):
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
                        if nm_type == '':
                            debug.debug('Requested symbol {0:s} in module {1:s} has multiple definitions and no type given\n'.format(sym_name, module))
                            return None
                        else:
                            for (addr, stype) in sym_list:

                                if stype == nm_type:
                                    ret = addr
                                    break

                            if ret == None:
                                debug.error('Requested symbol {0:s} in module {1:s} could not be found\n'.format(sym_name, module))
                    else:
                        # get the address of the symbol
                        ret = sym_list[0][0]
                else:
                    debug.debug('Requested symbol {0:s} not found in module {1:s}\n'.format(sym_name, module))
            else:
                debug.info('Requested module {0:s} not found in symbol table\n'.format(module))

            return ret


    cls = AbstractFreebsdProfile
    cls.__name__ = profilename.replace('.', '_')

    return cls

################################
# Track down the zip files
# Push them through the factory
# Check whether ProfileModifications will work

new_classes = []

for path in set(plugins.__path__):
    for path, _, files in os.walk(path):
        for fn in files:
            if zipfile.is_zipfile(os.path.join(path, fn)):
                new_classes.append(FreebsdProfileFactory(zipfile.ZipFile(os.path.join(path, fn))))

################################

class proc(obj.CType):
    def get_process_address_space(self):
        if self.obj_vm.profile.metadata.get('arch', 'x86') == 'x86' and self.obj_vm.pae:
            process_as = self.obj_vm.__class__(self.obj_vm.base, self.obj_vm.get_config(), dtb = self.obj_vm.vtop(self.p_vmspace.vm_pmap.pm_pdpt), skip_as_check = True)
        elif self.obj_vm.profile.metadata.get('arch', 'x86') == 'x86':
            process_as = self.obj_vm.__class__(self.obj_vm.base, self.obj_vm.get_config(), dtb = self.obj_vm.vtop(self.p_vmspace.vm_pmap.pm_pdir), skip_as_check = True)
        # Around 9.3 precomputed cr3 became part of the structure
        elif self.obj_vm.profile.metadata.get('arch', 'x86') == 'x64' and hasattr(self.p_vmspace.vm_pmap, "pm_cr3"):
            if self.p_vmspace.vm_pmap.pm_ucr3 != 0xffffffffffffffffL:
                process_as = self.obj_vm.__class__(self.obj_vm.base, self.obj_vm.get_config(), dtb = self.p_vmspace.vm_pmap.pm_ucr3, skip_as_check = True)
            else:
                process_as = self.obj_vm.__class__(self.obj_vm.base, self.obj_vm.get_config(), dtb = self.p_vmspace.vm_pmap.pm_cr3, skip_as_check = True)
        elif self.obj_vm.profile.metadata.get('arch', 'x86') == 'x64' and hasattr(self.p_vmspace.vm_pmap, "pm_pml4"):
            process_as = self.obj_vm.__class__(self.obj_vm.base, self.obj_vm.get_config(), dtb = self.obj_vm.vtop(self.p_vmspace.vm_pmap.pm_pml4), skip_as_check = True)
        else:
            raise RuntimeError('Unknown pmap structure')

        process_as.name = 'Process {0}'.format(self.p_pid)

        return process_as

    def get_proc_maps(self):
       entry = self.p_vmspace.vm_map.header.next

       while entry.v() != self.p_vmspace.vm_map.header.v():
           if entry.eflags & 0x2 == 0:
               # Skip MAP_ENTRY_IS_SUB_MAP
               yield entry
           entry = entry.next

    def psenv(self):
        process_as = self.get_process_address_space()

        if self.p_sysent.sv_flags & 0x100 == 0 or self.obj_vm.profile.metadata.get('memory_model', '32bit') == '32bit':
            # SV_ILP32 not set or 32bit
            ps_strings = obj.Object('ps_strings', offset = self.p_sysent.sv_psstrings, vm = process_as)
            ps_envstr = ps_strings.ps_envstr.dereference_as('Array', targetType = 'Pointer', count = ps_strings.ps_nenvstr)
        else:
            # SV_ILP32 on 64bit
            ps_strings = obj.Object('freebsd32_ps_strings', offset = self.p_sysent.sv_psstrings, vm = process_as)
            ps_envstr = ps_strings.ps_envstr.dereference_as('Array', targetType = 'Pointer32', count = ps_strings.ps_nenvstr)

        for s in ps_envstr:
            vals = s.dereference_as('String', length = 1024)
            ents = vals.split('=', 1)
            if len(ents) == 2:
                yield ents[0], ents[1]

    def get_environment(self):
        env = ' '.join(['{0}={1}'.format(key, value) for key, value in self.psenv()])

        return env

    def get_commandline(self):
        process_as = self.get_process_address_space()

        if self.p_sysent.sv_flags & 0x100 == 0 or self.obj_vm.profile.metadata.get('memory_model', '32bit') == '32bit':
            # SV_ILP32 not set or 32bit
            ps_strings = obj.Object('ps_strings', offset = self.p_sysent.sv_psstrings, vm = process_as)
            ps_argvstr = ps_strings.ps_argvstr.dereference_as('Array', targetType = 'Pointer', count = ps_strings.ps_nargvstr)
        else:
            # SV_ILP32 on 64bit
            ps_strings = obj.Object('freebsd32_ps_strings', offset = self.p_sysent.sv_psstrings, vm = process_as)
            ps_argvstr = ps_strings.ps_argvstr.dereference_as('Array', targetType = 'Pointer32', count = ps_strings.ps_nargvstr)

        name = ' '.join([str(s.dereference_as('String', length = 1024)) for s in ps_argvstr])

        return name

    def lsof(self):
        if self.p_fd.fd_lastfile != -1:
            # This is the most recent version with a separate table struct for filedescent structs
            if hasattr(self.p_fd, "fd_files"):
                filedescents = obj.Object('Array', offset = self.p_fd.fd_files.fdt_ofiles.obj_offset, vm = self.obj_vm, targetType = 'filedescent', count = self.p_fd.fd_lastfile + 1)
                files = (i.fde_file for i in filedescents)
            # In 8.4.0, type of fd_ofiles is `struct file **`
            elif hasattr(self.p_fd, "fd_ofiles") \
                    and isinstance(self.p_fd.fd_ofiles, obj.Pointer) \
                    and isinstance(self.p_fd.fd_ofiles.dereference(), obj.Pointer) \
                    and self.p_fd.fd_ofiles.dereference().dereference().obj_type == "file":
                fileptrs = obj.Object('Array', offset = self.p_fd.fd_ofiles, vm = self.obj_vm, targetType = 'Pointer', count = self.p_fd.fd_lastfile + 1)
                files = (i.dereference_as("file") for i in fileptrs)
            else:
                raise RuntimeError("Unknown filedesc structure")

            for n, f in enumerate(files):
                if f:
                    yield f, n

class vm_map_entry(obj.CType):
    def get_perms(self):
        permask = 'rwx'
        perms = ''

        for (ctr, i) in enumerate([1, 3, 5]):
            if (self.protection & i) == i:
                perms = perms + permask[ctr]
            else:
                perms = perms + '-'

        return perms

    def get_type(self):
        vm_object = self.object.vm_object

        if vm_object.v() == 0:
            return 'NONE'

        while vm_object.backing_object.v():
            vm_object = vm_object.backing_object

        return str(vm_object.type)

    def get_path(self):
        vm_object = self.object.vm_object

        if vm_object.v() == 0:
            return ''

        while vm_object.backing_object.v():
            vm_object = vm_object.backing_object

        if vm_object.type != 2:
            return ''

        vnode = vm_object.handle.dereference_as('vnode')
        return vnode.get_vpath()


class vnode(obj.CType):
    def get_vpath(self):
        """Lookup pathname of a vnode in the namecache"""
        rootvnode_addr = self.obj_vm.profile.get_symbol('rootvnode')
        rootvnode = obj.Object('Pointer', offset = rootvnode_addr, vm = self.obj_vm)
        vp = self
        components = list()

        while vp.v():
            if vp.v() == rootvnode.v():
                if len(components) == 0:
                    components.insert(0, '/')
                else:
                    components.insert(0, '')
                break

            if vp.v_vflag & 0x1 != 0:
                # VV_ROOT set
                vp = vp.v_mount.mnt_vnodecovered
            else:
                ncp = vp.v_cache_dst.tqh_first
                if ncp.v():
                    ncn = obj.Object('String', offset = ncp.nc_name.obj_offset, vm = self.obj_vm, length = ncp.nc_nlen)
                    components.insert(0, str(ncn))
                    vp = ncp.nc_dvp
                else:
                    break

        if components:
            return '/'.join(components)
        else:
            return ''


class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def generate_suggestions(self):
        """Tries to locate the DTB."""
        profile = self.obj_vm.profile
        kernbase = profile.get_symbol('kernbase')

        if profile.get_symbol('IdlePDPT') and profile.get_symbol('tramp_idleptd'):
            # PAE after 4/4G split
            ret = profile.get_symbol('IdlePDPT')
            ret = self.obj_vm.read(ret, 4)
            ret = struct.unpack("<I", ret)[0]
            if ret:
                yield ret
            # else: i386 without PAE after merge of PAE and non-PAE pmaps into same kernel

        if profile.get_symbol('IdlePDPT') and not profile.get_symbol('tramp_idleptd'):
            # PAE before 4/4G split
            ret = profile.get_symbol('IdlePDPT') - kernbase
            ret = self.obj_vm.read(ret, 4)
            ret = struct.unpack("<I", ret)[0]
            yield ret

        if profile.get_symbol('IdlePTD_nopae'):
            # i386 without PAE after merge of PAE and non-PAE pmaps into same kernel
            ret = profile.get_symbol('IdlePTD_nopae')
            ret = self.obj_vm.read(ret, 4)
            ret = struct.unpack("<I", ret)[0]
            yield ret

        if profile.get_symbol('IdlePTD') and profile.get_symbol('tramp_idleptd'):
            # i386 after 4/4G split
            ret = profile.get_symbol('IdlePTD')
            ret = self.obj_vm.read(ret, 4)
            ret = struct.unpack("<I", ret)[0]
            yield ret

        if profile.get_symbol('IdlePTD') and not profile.get_symbol('tramp_idleptd'):
            # i386 before 4/4G split
            ret = profile.get_symbol('IdlePTD') - kernbase
            ret = self.obj_vm.read(ret, 4)
            ret = struct.unpack("<I", ret)[0]
            yield ret

        if profile.get_symbol('KPML4phys'):
            # amd64
            ret = profile.get_symbol('KPML4phys') - kernbase
            ret = self.obj_vm.read(ret, 8)
            ret = struct.unpack("<Q", ret)[0]
            yield ret


class VolatilityFreebsdValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid FreeBSD Paged space"""

    def generate_suggestions(self):
        version_addr = self.obj_vm.profile.get_symbol('version')
        version = obj.Object('String', offset = version_addr, vm = self.obj_vm, length = 256)

        if version and version.startswith('FreeBSD'):
            yield True
        else:
            yield False


class FreebsdOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'freebsd'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.merge_overlay(freebsd_overlay)

class cdev(obj.CType):

    @property
    def si_name(self):
        orig = self.m("si_name")
        # in versions before 9.1.0, this member is a char pointer
        if isinstance(orig, obj.Pointer):
            return obj.Object("String", offset=orig.v(), vm=self.obj_vm, length=64)
        # after that the indirection was removed and the statically allocated
        # array is used directly
        else:
            return obj.Object("String", offset=orig.obj_offset, vm=self.obj_vm, length=64)


class FreebsdObjectClasses(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'freebsd'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.object_classes.update({
            'VolatilityDTB': VolatilityDTB,
            'VolatilityFreebsdValidAS' : VolatilityFreebsdValidAS,
            'IpAddress': basic.IpAddress,
            'Ipv6Address': basic.Ipv6Address,
            'proc': proc,
            'vm_map_entry': vm_map_entry,
            'vnode': vnode,
            'cdev': cdev,
            })
