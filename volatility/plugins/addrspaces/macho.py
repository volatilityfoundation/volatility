# Volatility
#
# Authors:
# Mike Auty
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

import struct
import volatility.plugins.addrspaces.standard as standard
import volatility.obj as obj
import volatility.addrspace as addrspace

macho_types = {
 'fat_header': [ 0x8, {
    'magic': [0x0, ['unsigned int']],
    'nfat_arch': [0x4, ['unsigned int']],
}],
 'fat_arch': [ 0x14, {
    'cputype': [0x0, ['int']],
    'cpusubtype': [0x4, ['int']],
    'offset': [0x8, ['unsigned int']],
    'size': [0xc, ['unsigned int']],
    'align': [0x10, ['unsigned int']],
}],
 'mach_header_64': [ 0x20, {
    'magic': [0x0, ['unsigned int']],
    'cputype': [0x4, ['int']],
    'cpusubtype': [0x8, ['int']],
    'filetype': [0xc, ['unsigned int']],
    'ncmds': [0x10, ['unsigned int']],
    'sizeofcmds': [0x14, ['unsigned int']],
    'flags': [0x18, ['unsigned int']],
    'reserved': [0x1c, ['unsigned int']],
}],
 'mach_header': [ 0x1c, {
    'magic': [0x0, ['unsigned int']],
    'cputype': [0x4, ['int']],
    'cpusubtype': [0x8, ['int']],
    'filetype': [0xc, ['unsigned int']],
    'ncmds': [0x10, ['unsigned int']],
    'sizeofcmds': [0x14, ['unsigned int']],
    'flags': [0x18, ['unsigned int']],
}],
 'symtab_command': [ 0x18, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
    'symoff': [0x8, ['unsigned int']],
    'nsyms': [0xc, ['unsigned int']],
    'stroff': [0x10, ['unsigned int']],
    'strsize': [0x14, ['unsigned int']],
}],
'load_command': [ 0x8, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
}],
'segment_command': [ 0x38, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
    'segname': [0x8, ['String', dict(length = 16)]],
    'vmaddr': [0x18, ['unsigned int']],
    'vmsize': [0x1c, ['unsigned int']],
    'fileoff': [0x20, ['unsigned int']],
    'filesize': [0x24, ['unsigned int']],
    'maxprot': [0x28, ['int']],
    'initprot': [0x2c, ['int']],
    'nsects': [0x30, ['unsigned int']],
    'flags': [0x34, ['unsigned int']],
}],
'segment_command_64': [ 0x48, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
    'segname': [0x8, ['String', dict(length = 16)]],
    'vmaddr': [0x18, ['unsigned long long']],
    'vmsize': [0x20, ['unsigned long long']],
    'fileoff': [0x28, ['unsigned long long']],
    'filesize': [0x30, ['unsigned long long']],
    'maxprot': [0x38, ['int']],
    'initprot': [0x3c, ['int']],
    'nsects': [0x40, ['unsigned int']],
    'flags': [0x44, ['unsigned int']],
}],
'symtab_command': [ 0x18, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
    'symoff': [0x8, ['unsigned int']],
    'nsyms': [0xc, ['unsigned int']],
    'stroff': [0x10, ['unsigned int']],
    'strsize': [0x14, ['unsigned int']],
}],
 'section_64': [ 0x50, {
    'sectname': [0x0, ['array', 16, ['char']]],
    'segname': [0x10, ['array', 16, ['char']]],
    'addr': [0x20, ['unsigned long long']],
    'size': [0x28, ['unsigned long long']],
    'offset': [0x30, ['unsigned int']],
    'align': [0x34, ['unsigned int']],
    'reloff': [0x38, ['unsigned int']],
    'nreloc': [0x3c, ['unsigned int']],
    'flags': [0x40, ['unsigned int']],
    'reserved1': [0x44, ['unsigned int']],
    'reserved2': [0x48, ['unsigned int']],
    'reserved3': [0x4c, ['unsigned int']],
}],
'section': [ 0x44, {
    'sectname': [0x0, ['array', 16, ['char']]],
    'segname': [0x10, ['array', 16, ['char']]],
    'addr': [0x20, ['unsigned int']],
    'size': [0x24, ['unsigned int']],
    'offset': [0x28, ['unsigned int']],
    'align': [0x2c, ['unsigned int']],
    'reloff': [0x30, ['unsigned int']],
    'nreloc': [0x34, ['unsigned int']],
    'flags': [0x38, ['unsigned int']],
    'reserved1': [0x3c, ['unsigned int']],
    'reserved2': [0x40, ['unsigned int']],
}],
}

class MachoTypes(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(macho_types)

class MachOAddressSpace(addrspace.AbstractRunBasedMemory):
    """ 
    Address space for mach-o files to support atc-ny memory reader

    The created mach-o file has a bunch of segments that contain the address of the section and the size
    From there we can translate between incoming address requests to memory contents
    """
    order = 1
    cache = False
    pae = True
    checkname = 'MachOValidAS'

    def __init__(self, base, config, *args, **kwargs):
        self.as_assert(base, "mac: need base")

        addrspace.AbstractRunBasedMemory.__init__(self, base, config, *args, **kwargs)

        sig = base.read(0, 4) 

        if sig == '\xce\xfa\xed\xfe':
            self.bits = 32
        elif sig == '\xcf\xfa\xed\xfe':
            self.bits = 64
        else:
            self.as_assert(0, "MachO Header signature invalid")

        self.runs = []

        self.header = None

        self.addr_cache = {}
        self.parse_macho()

    def get_object_name(self, object):
        if self.bits == 64 and object in ["mach_header", "segment_command", "section"]:
            object = object + "_64"

        return object

    def get_available_addresses(self):
        for vmaddr, _, vmsize in self.runs:
            yield vmaddr, vmsize

    def get_header(self):
        return self.header

    def parse_macho(self):
        self.runs = []
 
        header_name = self.get_object_name("mach_header")
        header_size = self.profile.get_obj_size(header_name)

        self.header = obj.Object(header_name, 0, self.base)
        offset = header_size

        self.segs = []

        for i in xrange(0, self.header.ncmds):
            structname = self.get_object_name("segment_command")
            seg = obj.Object(structname, offset, self.base)
            self.segs.append(seg)
            # Since these values will be used a lot, make sure they aren't reread (ie, no objects in the runs list)
            run = (int(seg.vmaddr), int(seg.fileoff), int(seg.vmsize))
            self.runs.append(run)
            offset = offset + seg.cmdsize
