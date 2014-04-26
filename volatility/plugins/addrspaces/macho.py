# Volatility
#
# Authors:
# Mike Auty
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

class MachOAddressSpace(addrspace.AbstractRunBasedMemory):
    """ 
    Address space for mach-o files to support atc-ny memory reader

    The created mach-o file has a bunch of segments that contain the address of the section and the size
    From there we can translate between incoming address requests to memory contents
    """
    order = 1
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
