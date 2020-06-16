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
    _valid_dtb_base = None
    _entry_addressmask = ((1 << 47) - 1) & (~0xfff)

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
            entry_addressbits = entry & self._entry_addressmask
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

        # if we already had a valid dtb - it was the single TTBR1, and should
        # be used to translate all kernel-space
        if type(self)._valid_dtb_base and (vaddr >> 63):
            return self.ptbl_walk(vaddr, type(self)._valid_dtb_base)
        else:
            return self.ptbl_walk(vaddr, self.dtb)

    def set_curr_base_valid(self):
        cls = type(self)
        if not cls._valid_dtb_base:
            cls._valid_dtb_base = self.dtb

    def get_available_pages(self):
        level = 0
        ptbl_descs = [self.dtb, 0, 0, 0]
        ptbl_indexes = [0, 0, 0, 0]
        while True:
            if ptbl_indexes[level] == 512:
                if level == 0:
                    break
                level -= 1
                ptbl_indexes[level] += 1
                continue

            entry = self.read_longlong_phys(ptbl_descs[level] + (ptbl_indexes[level] << 3))

            # entry points to next table
            if ((level < 3) and (entry & 0x3 == 0x3)):
                level += 1
                entry_addressbits = entry & self._entry_addressmask
                ptbl_descs[level] = entry_addressbits
                ptbl_indexes[level] = 0
                continue

            # entry points to physical address
            if (level == 3 and (entry & 0x3 == 0x3)) or (entry & 0x3 == 0x1):
                vaddr = 0
                for ilvl in xrange(level+1):
                    vaddr += ptbl_indexes[ilvl] << self.ptbl_lowbits(ilvl)
                yield vaddr, (1 << self.ptbl_lowbits(level))

            ptbl_indexes[level] += 1

