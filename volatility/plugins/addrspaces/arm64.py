# Volatility
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
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.plugins.addrspaces.paged as paged


class Arm64AddressSpace(paged.AbstractWritablePagedMemory):
    """Address space for ARM64 processors"""

    order = 800
    pae = False
    paging_address_space = True
    checkname = 'Arm64ValidAS'
    minimum_size = 0x1000
    alignment_gcd = 0x1000
    _longlong_struct = struct.Struct('<Q')

    def read_longlong_phys(self, addr):
        '''
        Returns an unsigned 64-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        try:
            string = self.base.read(addr, 8)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Could not read_longlong_phys at offset " + hex(addr))
        longlongval, = self._longlong_struct.unpack(string)
        return longlongval

    def ptbl_lowbits(self, level):
        return 12 + 9 * (3 - level)

    def ptbl_index(self, vaddr, level):
        return (vaddr >> self.ptbl_lowbits(level)) & 0x1ff

    def ptbl_walk(self, vaddr, base):
        if (vaddr == 0):
            return None
        for level in xrange(4):
            index = self.ptbl_index(vaddr, level)
            entry = self.read_longlong_phys(base + (index << 3))
            if not entry:
                return None
            # clear high bits
            entry_addressbits = entry & ((1 << 47) - 1)
            # clear low bits
            entry_addressbits = entry_addressbits & (~0xfff)
            # entry not valid
            if not (entry & 0x1):
                return None
            if (level == 3 and (entry & 0x3 != 0x3)):
                return None
            # entry points to final address
            if (level == 3 or (entry & 0x3 == 0x1)):
                lowbitmask = (1 << self.ptbl_lowbits(level)) - 1
                return entry_addressbits & (~lowbitmask) | (vaddr & lowbitmask)
            # entry points to next table
            base = entry_addressbits
        return None

    def vtop(self, vaddr):
        debug.debug("\n--vtop start: {0:x}".format(vaddr), 4)

        return self.ptbl_walk(vaddr, self.dtb)

    # FIXME
    # this is supposed to return all valid physical addresses based on the current dtb
    # this (may?) be painful to write due to ARM's different page table types and having small & large pages inside of those
    def get_available_pages(self):

        for i in xrange(0, (2 ** 32) - 1, 4096):
            yield (i, 0x1000)
