# Volatility
# Copyright (C) 2013 Volatility Foundation
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2004,2005,2006 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
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

import struct
import volatility.plugins.addrspaces.paged as paged
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611

class IA32PagedMemory(paged.AbstractWritablePagedMemory):
    """ Standard IA-32 paging address space.

    This class implements the IA-32 paging address space. It is responsible
    for translating each virtual (linear) address to a physical address.
    This is accomplished using hierachical paging structures.
    Every paging structure is 4096 bytes and is composed of entries.
    Each entry is 32 bits.  The first paging structure is located at the
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
    order = 70
    cache = False
    pae = False
    paging_address_space = True
    checkname = 'IA32ValidAS'
    # Hardcoded page info to avoid expensive recalculation
    minimum_size = 0x1000
    alignment_gcd = 0x1000

    def __init__(self, base, config, dtb = 0, skip_as_check = False, *args, **kwargs):
        ## We must be stacked on someone else:
        self.as_assert(base, "No base Address Space")

        paged.AbstractWritablePagedMemory.__init__(self, base, config, dtb = dtb, skip_as_check = skip_as_check, *args, **kwargs)

    def is_valid_profile(self, profile):
        return profile.metadata.get('memory_model', '32bit') == '32bit' or profile.metadata.get('os', 'Unknown').lower() == 'mac'

    def _cache_values(self):
        '''
        This method builds an address translation cache 
        of Page Directory Entries. This should only be used
        when you are analyzing a static sample of memory. 
        The size of the cache is based on the fact that the
        the Page Directory is one page of memory (0x1000) and
        entries are 4 Bytes in size. Thus, there are
        0x400 entries.
        '''
        pdir = self.base.read(self.dtb, 0x1000)
        if pdir:
            self.pde_cache = struct.unpack('<' + 'I' * 0x400, pdir)
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

    def pde_index(self, vaddr):
        ''' 
        Extracts the Page Directory Index number from the linear
        address. This corresponds to bits 31:22 of the virtual address.
        These 10 bits are used to select the entry in the Page Directory.
        '''
        return (vaddr >> 22) & 0x3FF

    def get_pde(self, vaddr):
        '''
        This method returns the Page Directory entry obtained by using
        bit (31:12) from CR3 with bits (11:2) from the linear address. 

        "Bits 11:2 are bits 31:22 of the linear address" [Intel]
        "Bits 31:12 are from CR3" [Intel]
        '''
        if self.cache:
            return self.pde_cache[self.pde_index(vaddr)]

        pde_paddr = ((vaddr & 0xffc00000) >> 20) | (self.dtb & 0xfffff000)
        return self.read_long_phys(pde_paddr)

    def get_pte(self, vaddr, pde):
        '''
        This method returns the Page Table entry obtained by using the 
        Table bits (21:12) from the linear address to specify the entry 
        offset from the supplied Page Directory entry (31:12).

        "Bits 11:2 are bits 21:12 of the linear address" [Intel]
        "Bits 31:12 are from the PDE" [Intel]
        '''
        pte_paddr = ((vaddr & 0x3ff000) >> 10) | (pde & 0xfffff000)
        return self.read_long_phys(pte_paddr)

    def get_paddr(self, vaddr, pte):
        '''
        This method returns the physical address of a 4-KByte page 
        obtained by combining  bits (31:12) from the Page Table entry with 
        bits (11:0) from the linear address.

        "Bits 11:0 are from the original linear address" [Intel]
        "Bits 31:12 are from the PTE" [Intel]
        '''
        return (vaddr & 0xfff) | (pte & 0xfffff000)

    def get_4MB_paddr(self, vaddr, pde):
        '''
        If the Page Directory Entry represents a 4-MByte
        page, this method extracts the physical address 
        of the page.       

        "Bits 21:0 are from the original linear address" [Intel] 
        "Bits 31:22 are bits 31:22 of the PDE" [Intel]
        '''
        return (vaddr & 0x3fffff) | (pde & 0xffc00000)

    def vtop(self, vaddr):
        '''
        This method translates an address in the virtual
        address space to its associated physical address.
        Invalid entries should be handled with operating
        system abstractions.
        '''
        pde = self.get_pde(vaddr)
        if not self.entry_present(pde):
            return None

        if self.page_size_flag(pde):
            return self.get_4MB_paddr(vaddr, pde)

        pte = self.get_pte(vaddr, pde)
        if not self.entry_present(pte):
            return None

        return self.get_paddr(vaddr, pte)

    def read_long_phys(self, addr):
        '''
        This method returns a 32-bit little endian unsigned
        integer from the specified address in the physical address
        space. If the address cannot be accessed, then the method 
        returns None.
        '''
        try:
            string = self.base.read(addr, 4)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Could not read_long_phys at offset " + hex(addr))
        (longval,) = struct.unpack('<I', string)
        return longval

    def get_available_pages(self):
        '''
        This method generates a list of pages that are
        available within the address space. The entries in 
        list are composed of the virtual address of the page 
        and the size of the particular page (address, size).
        It walks the 0x1000/0x4  entries in each Page Directory and 
        Page Table to determine which pages are accessible.
        '''

        for pde in range(0, 0x400):
            vaddr = pde << 22
            pde_value = self.get_pde(vaddr)
            if not self.entry_present(pde_value):
                continue
            if self.page_size_flag(pde_value):
                yield (vaddr, 0x400000)
            else:
                tmp = vaddr
                for pte in range(0, 0x400):
                    vaddr = tmp | (pte << 12)
                    pte_value = self.get_pte(vaddr, pde_value)
                    if self.entry_present(pte_value):
                        yield (vaddr, 0x1000)

class IA32PagedMemoryPae(IA32PagedMemory):
    """ 
    This class implements the IA-32 PAE paging address space. It is responsible
    for translating each 32-bit virtual (linear) address to a 52-bit physical address.
    When PAE paging is in use, CR3 references the base of a 32-Byte Page Directory
    Pointer Table. 

    The 'cache' parameter is used to cache intermediate PDPTE entries
    within the paging hierarchy. This option is not recommended when
    the address space is being used on live systems as it could result
    in stale data.

    Additional Resources:
     - Intel(R) 64 and IA-32 Architectures Software Developer's Manual
       Volume 3A: System Programming Guide. Section 4.3
       http://www.intel.com/products/processor/manuals/index.htm
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
    pae = True

    def _cache_values(self):
        '''
        This method builds an address translation cache
        of Page Directory Pointer Table entries. This should 
        only be used when you are analyzing a static sample of memory
        '''
        pdpt = self.base.read(self.dtb, 0x20)
        if pdpt:
            self.pdpte_cache = struct.unpack('<' + 'Q' * 4, pdpt)
        else:
            self.cache = False

    def pdpte_index(self, vaddr):
        '''
        This method calculates the Page Directory Pointer Table
        index from bits 31:30 of the virtual address 
        '''
        return vaddr >> 30

    def get_pdpte(self, vaddr):
        '''
        This method returns the Page Directory Pointer entry for the
        virtual address. Bits 32:30 are used to select the appropriate
        8 byte entry in the Page Directory Pointer table. 

        Bits 4:3 are bits 31:30 of the linear address
        Bits 31:5 are from CR3
        '''
        if self.cache:
            return self.pdpte_cache[self.pdpte_index(vaddr)]

        pdpte_paddr = ((vaddr & 0xc0000000) >> 27) | (self.dtb & 0xffffffe0)
        return self.read_long_long_phys(pdpte_paddr)

    def get_pde(self, vaddr, pdpte):
        '''
        This method returns the Page Directory entry obtained by using
        bits (51:12) from PDPTE with bits (11:3) from the linear address.

        "Bits 11:3 are bits 29:21 of the linear address" [Intel]
        "Bits 51:12 are from the PDPTE" [Intel]
        '''
        pde_paddr = ((vaddr & 0x3fe00000) >> 18) | (pdpte & 0xffffffffff000)
        return self.read_long_long_phys(pde_paddr)

    def get_2MB_paddr(self, vaddr, pde):
        '''
        If the Page Directory Entry represents a 2-MByte
        page, this method extracts the physical address
        of the page.

        "Bits 51:21 are from the PDE" [Intel]
        "Bits 20:0 are from the original linear address" [Intel]
        '''
        return (vaddr & 0x1fffff) | (pde & 0xfffffffe00000)

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

        This code was derived directly from legacyintel.py
        '''
        pdpte = self.get_pdpte(vaddr)
        if not self.entry_present(pdpte):
            return None

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

        for pdpte in range(0, 4):
            vaddr = pdpte << 30
            pdpte_value = self.get_pdpte(vaddr)
            if not self.entry_present(pdpte_value):
                continue
            for pde in range(0, 0x200):
                vaddr = pdpte << 30 | (pde << 21)
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
