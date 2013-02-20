# Volatility
#
# Authors:
# Mike Auty
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

""" This is based on Jesse Kornblum's patch to clean up the standard AS's.
"""
import volatility.plugins.addrspaces.intel as intel
import struct

# WritablePagedMemory must be BEFORE base address, since it adds the concrete method get_available_addresses
# If it's second, BaseAddressSpace's abstract version will take priority
class AMD64PagedMemory(intel.JKIA32PagedMemoryPae):
    """ Standard AMD 64-bit address space.
    
    Provides an address space for AMD64 paged memory, aka the x86_64 
    architecture, which is laid out similarly to Physical Address 
    Extensions (PAE). Allows callers to map virtual address to 
    offsets in physical memory.

    Create a new AMD64 address space to sit on top of the base address 
    space and a Directory Table Base (CR3 value) of 'dtb'.

    If the 'cache' parameter is true, will cache the Page Directory Entries
    for extra performance. The cache option requires an additional 4KB of
    space.

    Comments in this class mostly come from the Intel(R) 64 and IA-32 
    Architectures Software Developer's Manual Volume 3A: System Programming 
    Guide, Part 1, revision 031, pages 4-8 to 4-15. This book is available
    for free at http://www.intel.com/products/processor/manuals/index.htm.
    Similar information is also available from Advanced Micro Devices (AMD) 
    at http://support.amd.com/us/Processor_TechDocs/24593.pdf.
    """
    order = 60
    cache = False
    pae = True
    checkname = 'AMD64ValidAS'
    paging_address_space = True

    def _cache_values(self):
        '''
        We cache the Page Map Level 4 Entries to avoid having to 
        look them up later. There are 0x200 entries of 64-bits each
        This means there are 0x1000 bytes of data
        '''
        buf = self.base.read(self.dtb & 0xffffffffff000, 0x1000)
        self.cache = False
        if buf:
            self.pml4e_cache = struct.unpack('<' + 'Q' * 0x200, buf)
        else:
            self.cache = False

    def is_valid_profile(self, profile):
        return profile.metadata.get('memory_model', '32bit') == '64bit'

    def pml4e_index(self, vaddr):
        ''' 
        Returns the Page Map Level 4 Entry Index number from the given
        virtual address. The index number is in bits 47:39.
        '''
        return (vaddr & 0xff8000000000) >> 39

    def get_pml4e(self, vaddr):
        '''
        Return the Page Map Level 4 Entry for the given virtual address.
        If caching

        Bits 51:12 are from CR3
        Bits 11:3 are bits 47:39 of the linear address
        Bits 2:0 are 0.
        '''
        if self.cache:
            return self.pml4e_cache[self.pml4e_index(vaddr)]

        pml4e_addr = (self.dtb & 0xffffffffff000) | ((vaddr & 0xff8000000000) >> 36)
        return self._read_long_long_phys(pml4e_addr)

    def get_pdpte(self, vaddr, pml4e):
        '''
        Return the Page Directory Pointer Table Entry for the given virtual address.
        
        Bits 51:12 are from the PML4E
        Bits 11:3 are bits 38:30 of the linear address
        Bits 2:0 are all 0
        '''
        pdpte_addr = (pml4e & 0xffffffffff000) | ((vaddr & 0x7FC0000000) >> 27)
        return self._read_long_long_phys(pdpte_addr)

    def get_one_gig_paddr(self, vaddr, pdpte):
        '''
        Return the offset in a 1GB memory page from the given virtual
        address and Page Directory Pointer Table Entry.

        Bits 51:30 are from the PDE
        Bits 29:0 are from the original linear address
        '''
        return (pdpte & 0xfffffc0000000) | (vaddr & 0x3fffffff)

    def vtop(self, vaddr):
        '''
        Translates virtual addresses into physical offsets.
        The function returns either None (no valid mapping)
        or the offset in physical memory where the address maps.
        '''
        vaddr = long(vaddr)
        pml4e = self.get_pml4e(vaddr)
        if not self.entry_present(pml4e):
            # Add support for paged out PML4E
            return None

        pdpte = self.get_pdpte(vaddr, pml4e)
        if not self.entry_present(pdpte):
            # Add support for paged out PDPTE
            # Insert buffalo here!
            return None

        if self.page_size_flag(pdpte):
            return self.get_one_gig_paddr(vaddr, pdpte)

        pde = self.get_pde(vaddr, pdpte)
        if not self.entry_present(pde):
            # Add support for paged out PDE
            return None

        if self.page_size_flag(pde):
            return self.get_two_meg_paddr(vaddr, pde)

        pte = self.get_pte(vaddr, pde)
        if not self.entry_present(pte):
            # Add support for paged out PTE
            return None

        return self.get_phys_addr(vaddr, pte)

    def get_available_pages(self):
        '''
        Return a list of lists of available memory pages.
        Each entry in the list is the starting virtual address 
        and the size of the memory page.
        '''

        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pml4e in range(0, 0x200):
            vaddr = pml4e << 39
            pml4e_value = self.get_pml4e(vaddr)
            if not self.entry_present(pml4e_value):
                continue
            for pdpte in range(0, 0x200):
                vaddr = (pml4e << 39) | (pdpte << 30)
                pdpte_value = self.get_pdpte(vaddr, pml4e_value)
                if not self.entry_present(pdpte_value):
                    continue
                if self.page_size_flag(pdpte_value):
                    yield (vaddr, 0x40000000)
                    continue
                tmp2 = vaddr
                for pde in range(0, 0x200):
                    vaddr = tmp2 | (pde << 21)
                    pde_value = self.get_pde(vaddr, pdpte_value)
                    if not self.entry_present(pde_value):
                        continue
                    if self.page_size_flag(pde_value):
                        yield (vaddr, 0x200000)
                        continue

                    tmp = vaddr
                    for pte in range(0, 0x200):
                        vaddr = tmp | (pte << 12)
                        pte_value = self.get_pte(vaddr, pde_value)
                        if self.entry_present(pte_value):
                            yield (vaddr, 0x1000)

    @classmethod
    def address_mask(cls, addr):
        return addr & 0xffffffffffff
