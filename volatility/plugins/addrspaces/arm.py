# Volatility
#
# Authors:
# attc - atcuno@gmail.com
# Joe Sylve - joe.sylve@gmail.com
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
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.plugins.addrspaces.paged as paged

class ArmAddressSpace(paged.AbstractWritablePagedMemory):
    order = 800
    pae = False
    paging_address_space = True
    checkname = 'ArmValidAS'
    minimum_size = 0x1000
    alignment_gcd = 0x1000

    def read_long_phys(self, addr):
        '''
        Returns an unsigned 32-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        try:
            string = self.base.read(addr, 4)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Could not read_long_phys at offset " + hex(addr))
        (longval,) = struct.unpack('<I', string)
        return longval

    def page_table_present(self, entry):
        if entry:
            return True # TODO FIXME
        return False

    # Page Directory Index (1st Level Index)
    def pde_index(self, vaddr):
        return (vaddr >> 20)

    # 1st Level Descriptor
    def pde_value(self, vaddr):
        return self.read_long_phys(self.dtb | (self.pde_index(vaddr) << 2))

    # 2nd Level Page Table Index (Course Pages)
    def pde2_index(self, vaddr):
        return ((vaddr >> 12) & 0x0FF)

    # 2nd Level Page Table Descriptor (Course Pages)
    def pde2_value(self, vaddr, pde):
        return self.read_long_phys((pde & 0xFFFFFC00) | (self.pde2_index(vaddr) << 2))

    # 2nd Level Page Table Index (Fine Pages)
    def pde2_index_fine(self, vaddr):
        return ((vaddr >> 10) & 0x3FF)

    # 2nd Level Page Table Descriptor (Fine Pages)
    def pde2_value_fine(self, vaddr, pde):
        return self.read_long_phys((pde & 0xFFFFF000) | (self.pde2_index_fine(vaddr) << 2))


    def get_pte(self, vaddr, pde_value):
        # page table
        if (pde_value & 0b11) == 0b00:
            # If bits[1:0] == 0b00, the associated modified virtual addresses are unmapped,
            # and attempts to access them generate a translation fault

            debug.debug("get_pte: invalid pde_value {0:x}".format(pde_value))
            return None

        elif (pde_value & 0b11) == 0b10:
            # If bits[1:0] == 0b10, the entry is a section descriptor for its associated modified virtual addresses.
            # If bit[18] is set, optional supersections are used, which we don't support yet

            issuper = int(pde_value & (1 << 18))

            if issuper:
                # TODO: Implement Supersection support if needed
                debug.warning("supersection found")
                return None
            else:
                return ((pde_value & 0xFFE00000) | (vaddr & 0x1FFFFF))

        elif (pde_value & 0b11) == 0b01:
            # If bits[1:0] == 0b01, the entry gives the physical address of a coarse second-level table, that specifies
            # how the associated 1MB modified virtual address range is mapped.
            pde2_value = self.pde2_value(vaddr, pde_value)

            if not pde2_value:
                debug.debug("no pde2_value", 4)
                return None

            if (pde2_value & 0b11) == 0b01:
                # 64K large pages
                return ((pde2_value & 0xFFFF0000) | (vaddr & 0x0000FFFF))
            elif (pde2_value & 0b11) == 0b10 or (pde2_value & 0b11) == 0b11:
                # 4K small pages
                return ((pde2_value & 0xFFFFF000) | (vaddr & 0x00000FFF))
            else:
                debug.warning("get_pte: invalid course pde2_value {0:x}".format(pde2_value))
                return None

        elif (pde_value & 0b11) == 0b11:
            # If bits[1:0] == 0b11, the entry gives the physical address of a fine second-level table. A fine
            # second-level page table specifies how the associated 1MB modified virtual address range is mapped.

            pde2_value = self.pde2_value_fine(vaddr, pde_value)

            if not pde2_value:
                debug.debug("no pde2_value", 4)
                return None

            if (pde2_value & 0b11) == 0b01:
                # 64K large pages
                return ((pde2_value & 0xFFFF0000) | (vaddr & 0x0000FFFF))
            elif (pde2_value & 0b11) == 0b10:
                # 4K small pages
                return ((pde2_value & 0xFFFFF000) | (vaddr & 0x00000FFF))
            elif (pde2_value & 0b11) == 0b11:
                #1k tiny pages
                return ((pde2_value & 0xFFFFFC00) | (vaddr & 0x3FF))
            else:
                debug.warning("get_pte: invalid fine pde2_value {0:x}".format(pde2_value))
                return None

    def vtop(self, vaddr):
        debug.debug("\n--vtop start: {0:x}".format(vaddr), 4)

        pde_value = self.pde_value(vaddr)

        if not pde_value:
            debug.debug("no pde_value", 4)
            return None

        debug.debug("!!!pde_value: {0:x}".format(pde_value), 4)

        pte_value = self.get_pte(vaddr, pde_value)

        return pte_value

    # FIXME
    # this is supposed to return all valid physical addresses based on the current dtb
    # this (may?) be painful to write due to ARM's different page table types and having small & large pages inside of those
    def get_available_pages(self):

        for i in xrange(0, (2 ** 32) - 1, 4096):
            yield (i, 0x1000)

