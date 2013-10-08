# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# Authors:
# attc - atcuno@gmail.com
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

import volatility.obj as obj
import volatility.addrspace as addrspace
import volatility.debug as debug

class LimeTypes(obj.ProfileModification):

    def modification(self, profile):

        profile.vtypes.update({
            'lime_header': [ 0x20, {
                'magic':     [0x0, ['unsigned int']],
                'version':   [0x4, ['unsigned int']],
                'start':     [0x8, ['unsigned long long']],
                'end':       [0x10, ['unsigned long long']],
                'reserved':  [0x18, ['unsigned long long']],
                }],
            })

class LimeAddressSpace(addrspace.AbstractRunBasedMemory):
    """ 
    Address space for Lime 
    """
    order = 2

    def __init__(self, base, config, *args, **kwargs):
        self.as_assert(base, "lime: need base")

        addrspace.AbstractRunBasedMemory.__init__(self, base, config, *args, **kwargs)

        sig = base.read(0, 4)

        ## ARM processors are bi-endian, but little is the default and currently
        ## the only mode we support; unless it comes a common request.
        if sig == '\x4c\x69\x4d\x45':
            debug.debug("Big-endian ARM not supported, please submit a feature request")

        self.as_assert(sig == '\x45\x4D\x69\x4c', "Invalid Lime header signature")

        self.addr_cache = {}
        self.parse_lime()

    def parse_lime(self):
        self.runs = []

        offset = 0

        header = obj.Object("lime_header", offset = offset, vm = self.base)

        while header.magic.v() == 0x4c694d45:

            #print "new segment at %x end %x size: %d offset %d | %x" % (header.start, header.end, header.end - header.start, offset, offset)

            # Since these values will be used a lot, make sure they aren't reread (ie, no objects in the runs list)
            seg = (int(header.start), offset + self.profile.get_obj_size("lime_header"), header.end - header.start + 1)
            self.runs.append(seg)

            offset = offset + seg[2] + self.profile.get_obj_size("lime_header")

            header = obj.Object("lime_header", offset = offset, vm = self.base)

    def translate(self, addr):
        """Find the offset in the file where a memory address can be found.
        @param addr: a memory address
        """
        firstram = self.runs[0][0]

        if addr < firstram:
            addr = firstram + addr

        return addrspace.AbstractRunBasedMemory.translate(self, addr)
