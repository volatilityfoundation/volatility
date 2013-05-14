# Volatility
# Copyright (C) 2013 Volatility Foundation
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

import volatility.plugins.addrspaces.paged as paged
import volatility.obj as obj
import struct

class AMD64PagedMemory(paged.AbstractWritablePagedMemory):
    """ Standard AMD 64-bit address space.
   
    This class implements the AMD64/IA-32E paging address space. It is responsible
    for translating each virtual (linear) address to a physical address.
    This is accomplished using hierachical paging structures.
    Every paging structure is 4096 bytes and is composed of entries.
    Each entry is 64 bits.  The first paging structure is located at the
    physical address found in CR3 (dtb).

    The 'cache' parameter is used to cache intermediate structures
    within the paging hierarchy. This option is not recommended when
    the address space is being used on live systems as it could result
    in stale data.

    Additional Resources:
     - Intel(R) 64 and IA-32 Architectures Software Developer's Manual
       Volume 3A: System Programming Guide. Section 4.3
       http://www.intel.com/products/processor/manuals/index.htm
     - AMD64 Architecture Programmer's Manual Volume 2: System Programming
       http://support.amd.com/us/Processor_TechDocs/24593_APM_v2.pdf
     - N. Petroni, A. Walters, T. Fraser, and W. Arbaugh, "FATKit: A Framework
       for the Extraction and Analysis of Digital Forensic Data from Volatile
       System Memory" ,Digital Investigation Journal 3(4):197-210, December 2006.
       (submitted February 2006)
     - N. P. Maclean, "Acquisition and Analysis of Windows Memory,"
       University of Strathclyde, Glasgow, April 2006.
     - Russinovich, M., & Solomon, D., & Ionescu, A.
       "Windows Internals, 5th Edition", Microsoft Press, 2009.
    """
    order = 60
    cache = False
    pae = True
    checkname = 'AMD64ValidAS'
    paging_address_space = True
    minimum_size = 0x1000
    alignment_gcd = 0x1000

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

    def entry_present(self, entry):
        '''
        Checks if the entry's 'P' flag (bit 0) is set or
        if the entry represents data in transition.
        '''
        if entry:
            if (entry & 1):
                return True

            # The page is in transition and not a prototype.
            # Thus, we will treat it as present.
            if (entry & (1 << 11)) and not (entry & (1 << 10)):
                return True

        return False

    def page_size_flag(self, entry):
        '''
        Checks if the entry's 'PS' Page Size (bit 7) is set
        '''
        if entry:
            return (entry & (1 << 7)) == (1 << 7)
        return False

    def get_2MB_paddr(self, vaddr, pde):
        '''
        If the Page Directory Entry represents a 2-MByte
        page, this method extracts the physical address
        of the page.

        "Bits 51:21 are from the PDE" [Intel]
        "Bits 20:0 are from the original linear address" [Intel]
        '''
        return (vaddr & 0x1fffff) | (pde & 0xfffffffe00000)

    def is_valid_profile(self, profile):
        '''
        This method checks to make sure the address space is being
        used with a supported profile. 
        '''
        return profile.metadata.get('memory_model', '32bit') == '64bit' or profile.metadata.get('os', 'Unknown').lower() == 'mac'

    def pml4e_index(self, vaddr):
        ''' 
        This method returns the Page Map Level 4 Entry Index 
        number from the given  virtual address. The index number is
        in bits 47:39.
        '''
        return (vaddr & 0xff8000000000) >> 39

    def get_pml4e(self, vaddr):
        '''
        This method returns the Page Map Level 4 (PML4) entry for the 
        virtual address. Bits 47:39 are used to the select the
        appropriate 8 byte entry in the Page Map Level 4 Table.

        "Bits 51:12 are from CR3" [Intel]
        "Bits 11:3 are bits 47:39 of the linear address" [Intel]
        "Bits 2:0 are 0" [Intel]
        '''
        if self.cache:
            return self.pml4e_cache[self.pml4e_index(vaddr)]

        pml4e_paddr = (self.dtb & 0xffffffffff000) | ((vaddr & 0xff8000000000) >> 36)
        return self.read_long_long_phys(pml4e_paddr)

    def get_pdpte(self, vaddr, pml4e):
        '''
        This method returns the Page Directory Pointer entry for the
        virtual address. Bits 32:30 are used to select the appropriate
        8 byte entry in the Page Directory Pointer table.
        
        "Bits 51:12 are from the PML4E" [Intel]
        "Bits 11:3 are bits 38:30 of the linear address" [Intel]
        "Bits 2:0 are all 0" [Intel]
        '''
        pdpte_paddr = (pml4e & 0xffffffffff000) | ((vaddr & 0x7FC0000000) >> 27)
        return self.read_long_long_phys(pdpte_paddr)

    def get_1GB_paddr(self, vaddr, pdpte):
        '''
        If the Page Directory Pointer Table entry represents a 1-GByte
        page, this method extracts the physical address of the page.

        "Bits 51:30 are from the PDPTE" [Intel]
        "Bits 29:0 are from the original linear address" [Intel]
        '''
        return (pdpte & 0xfffffc0000000) | (vaddr & 0x3fffffff)

    def get_pde(self, vaddr, pdpte):
        '''
        This method returns the Page Directory entry obtained by using
        bits (51:12) from PDPTE with bits (11:3) from the linear address.

        "Bits 51:12 are from the PDPTE" [Intel]
        "Bits 11:3 are bits 29:21 of the linear address" [Intel]
        "Bits 2:0 are 0" [Intel]
        '''
        pde_paddr = ((vaddr & 0x3fe00000) >> 18) | (pdpte & 0xffffffffff000)
        return self.read_long_long_phys(pde_paddr)

    def get_pte(self, vaddr, pde):
        '''
        This method returns the Page Table entry obtained by using the
        Table bits (20:12) from the linear address to specify the entry
        offset from the supplied Page Directory entry (51:12).

        "Bits 11:3 are bits 20:12 of the original linear address" [Intel]
        "Bits 51:12 are from the PDE" [Intel]
        '''
        pte_paddr = ((vaddr & 0x1ff000) >> 9) | (pde & 0xffffffffff000)
        return self.read_long_long_phys(pte_paddr)

    def get_paddr(self, vaddr, pte):
        '''
        This method returns the physical address of a 4-KByte page
        obtained by combining  bits (51:12) from the Page Table entry with
        bits (11:0) from th linear address.

        "Bits 11:0 are from the original linear address" [Intel]
        "Bits 51:12 are from the PTE" [Intel]
        '''
        return (vaddr & 0xfff) | (pte & 0xffffffffff000)

    def vtop(self, vaddr):
        '''
        This method translates an address in the virtual
        address space to its associated physical address.
        Invalid entries should be handled with operating
        system abstractions.
        '''
        vaddr = long(vaddr)
        pml4e = self.get_pml4e(vaddr)
        if not self.entry_present(pml4e):
            return None

        pdpte = self.get_pdpte(vaddr, pml4e)
        if not self.entry_present(pdpte):
            return None

        if self.page_size_flag(pdpte):
            return self.get_1GB_paddr(vaddr, pdpte)

        pde = self.get_pde(vaddr, pdpte)
        if not self.entry_present(pde):
            return None

        if self.page_size_flag(pde):
            return self.get_2MB_paddr(vaddr, pde)

        pte = self.get_pte(vaddr, pde)
        if not self.entry_present(pte):
            return None

        return self.get_paddr(vaddr, pte)

    def read_long_long_phys(self, addr):
        '''
        This method returns a 64-bit little endian
        unsigned integer from the specified address in the
        physical address space. If the address cannot be accessed,
        then the method returns None.

        This code was derived directly from legacyintel.py
        '''
        try:
            string = self.base.read(addr, 8)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Unable to read_long_long_phys at " + hex(addr))
        (longlongval,) = struct.unpack('<Q', string)
        return longlongval

    def get_available_pages(self):
        '''
        This method generates a list of pages that are
        available within the address space. The entries in
        list are composed of the virtual address of the page
        and the size of the particular page (address, size).
        It walks the 0x1000/0x8  entries in each Page Directory and
        Page Table to determine which pages are accessible.

        This code was derived directly from legacyintel.py.
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
