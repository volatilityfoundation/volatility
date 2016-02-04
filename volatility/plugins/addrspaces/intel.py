# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2004,2005,2006 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
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
import volatility.plugins.addrspaces.paged as paged
import volatility.obj as obj

entry_size = 8
pointer_size = 4
page_shift = 12
ptrs_per_pte = 1024
ptrs_per_pgd = 1024
ptrs_per_pae_pte = 512
ptrs_per_pae_pgd = 512
ptrs_per_pdpi = 4
pgdir_shift = 22
pdpi_shift = 30
pdptb_shift = 5
pde_shift = 21
ptrs_per_pde = 512
ptrs_page = 2048

class IA32PagedMemory(paged.AbstractWritablePagedMemory):
    """ Standard IA-32 paging address space.

    This class implements the IA-32 paging address space. It is responsible
    for translating each virtual (linear) address to a physical address.
    This is accomplished using hierachical paging structures.
    Every paging structure is 4096 bytes and is composed of entries.
    Each entry is 32 bits.  The first paging structure is located at the
    physical address found in CR3 (dtb).

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
    pae = False
    paging_address_space = True
    checkname = 'IA32ValidAS'
    # Hardcoded page info to avoid expensive recalculation
    minimum_size = 0x1000
    alignment_gcd = 0x1000
    _long_struct = struct.Struct('<I')

    def __init__(self, base, config, dtb = 0, skip_as_check = False, *args, **kwargs):
        ## We must be stacked on someone else:
        self.as_assert(base, "No base Address Space")

        paged.AbstractWritablePagedMemory.__init__(self, base, config, dtb = dtb, skip_as_check = skip_as_check, *args, **kwargs)

    def is_valid_profile(self, profile):
        return profile.metadata.get('memory_model', '32bit') == '32bit' or profile.metadata.get('os', 'Unknown').lower() == 'mac'

    def entry_present(self, entry):
        if entry:
            if (entry & 1):
                return True

            arch = self.profile.metadata.get('os', 'Unknown').lower()

            # The page is in transition and not a prototype.
            # Thus, we will treat it as present.
            if arch == "windows" and ((entry & (1 << 11)) and not (entry & (1 << 10))):
                return True

            # Linux pages that have had mprotect(...PROT_NONE) called on them
            # have the present bit cleared and global bit set
            if arch == "linux" and (entry & (1 << 8)):
                return True

        return False

    def page_size_flag(self, entry):
        if (entry & (1 << 7)) == (1 << 7):
            return True
        return False

    def is_user_page(self, entry):
        return entry & (1 << 2) == (1 << 2)

    def is_supervisor_page(self, entry):
        return not self.is_user_page(entry)

    def is_writeable(self, entry):
        return entry & (1 << 1) == (1 << 1)
        
    def is_dirty(self, entry):
        return entry & (1 << 6) == (1 << 6)
        
    def is_nx(self, entry):
        return False
        
    def is_accessed(self, entry):
        return entry & (1 << 5) == (1 << 5)
        
    def is_copyonwrite(self, entry):
        return entry & (1 << 9) == (1 << 9)

    def is_prototype(self, entry):
        return entry & (1 << 10) == (1 << 10)

    def pgd_index(self, pgd):
        return (pgd >> pgdir_shift) & (ptrs_per_pgd - 1)

    def get_pgd(self, vaddr):
        pgd_entry = self.dtb + self.pgd_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte >> page_shift

    def pte_index(self, pte):
        return (pte >> page_shift) & (ptrs_per_pte - 1)

    def get_pte(self, vaddr, pgd):
        pgd_val = pgd & ~((1 << page_shift) - 1)
        pgd_val = pgd_val + self.pte_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return (self.pte_pfn(pte) << page_shift) | (vaddr & ((1 << page_shift) - 1))

    def get_four_meg_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & ((ptrs_per_pgd - 1) << 22)) | (vaddr & ~((ptrs_per_pgd - 1) << 22))

    def vtop(self, vaddr):
        retVal = None
        pgd = self.get_pgd(vaddr)
        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal = self.get_four_meg_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if not pte:
                    return None
                if self.entry_present(pte):
                    retVal = self.get_paddr(vaddr, pte)
        return retVal

    def read_long_phys(self, addr):
        try:
            string = self.base.read(addr, 4)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Unable to read_long_phys at " + hex(addr))
        longval, = self._long_struct.unpack(string)
        return longval

    def get_available_pages(self, with_pte = False):
        pgd_curr = self.dtb
        for i in range(0, ptrs_per_pgd):
            start = (i * ptrs_per_pgd * ptrs_per_pte * 4)
            entry = self.read_long_phys(pgd_curr)
            pgd_curr = pgd_curr + 4
            if self.entry_present(entry) and self.page_size_flag(entry):
                if with_pte: 
                    yield (entry, start, 0x400000)
                else:
                    yield (start, 0x400000)
            elif self.entry_present(entry):
                pte_curr = entry & ~((1 << page_shift) - 1)
                for j in range(0, ptrs_per_pte):
                    pte_entry = self.read_long_phys(pte_curr)
                    pte_curr = pte_curr + 4
                    if self.entry_present(pte_entry):
                        if with_pte: 
                            yield (pte_entry, start + j * 0x1000, 0x1000)
                        else:
                            yield (start + j * 0x1000, 0x1000)

class IA32PagedMemoryPae(IA32PagedMemory):
    """
    This class implements the IA-32 PAE paging address space. It is responsible
    for translating each 32-bit virtual (linear) address to a 52-bit physical address.
    When PAE paging is in use, CR3 references the base of a 32-Byte Page Directory
    Pointer Table.

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
    _longlong_struct = struct.Struct('<Q')

    def get_pdptb(self, pdpr):
        return pdpr & 0xFFFFFFE0

    def pdpi_index(self, pdpi):
        return (pdpi >> pdpi_shift)

    def get_pdpi(self, vaddr):
        pdpi_entry = self.get_pdptb(self.dtb) + self.pdpi_index(vaddr) * entry_size
        return self._read_long_long_phys(pdpi_entry)

    def pde_index(self, vaddr):
        return (vaddr >> pde_shift) & (ptrs_per_pde - 1)

    def pdba_base(self, pdpe):
        return pdpe & 0xFFFFFFFFFF000

    def get_pgd(self, vaddr, pdpe):
        pgd_entry = self.pdba_base(pdpe) + self.pde_index(vaddr) * entry_size
        return self._read_long_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte & 0xFFFFFFFFFF000

    def pte_index(self, vaddr):
        return (vaddr >> page_shift) & (ptrs_per_pde - 1)

    def ptba_base(self, pde):
        return pde & 0xFFFFFFFFFF000

    def get_pte(self, vaddr, pgd):
        pgd_val = self.ptba_base(pgd) + self.pte_index(vaddr) * entry_size
        return self._read_long_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return self.pte_pfn(pte) | (vaddr & ((1 << page_shift) - 1))

    def get_large_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & 0xFFFFFFFE00000) | (vaddr & ~((ptrs_page - 1) << 21))

    def vtop(self, vaddr):
        retVal = None
        pdpe = self.get_pdpi(vaddr)

        if not self.entry_present(pdpe):
            return retVal

        pgd = self.get_pgd(vaddr, pdpe)
        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal = self.get_large_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if self.entry_present(pte):
                    retVal = self.get_paddr(vaddr, pte)

        return retVal

    def _read_long_long_phys(self, addr):
        if not addr:
            return obj.NoneObject("Unable to read None")

        try:
            string = self.base.read(addr, 8)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Unable to read base AS at " + hex(addr))
        longlongval, = self._longlong_struct.unpack(string)
        return longlongval

    def get_available_pages(self, with_pte = False):

        pdpi_base = self.get_pdptb(self.dtb)

        for i in range(0, ptrs_per_pdpi):

            start = (i * ptrs_per_pae_pgd * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
            pdpi_entry = pdpi_base + i * entry_size
            pdpe = self._read_long_long_phys(pdpi_entry)

            if not self.entry_present(pdpe):
                continue

            pgd_curr = self.pdba_base(pdpe)

            for j in range(0, ptrs_per_pae_pgd):
                soffset = start + (j * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
                entry = self._read_long_long_phys(pgd_curr)
                pgd_curr = pgd_curr + 8
                if self.entry_present(entry) and self.page_size_flag(entry):
                    if with_pte:
                        yield (entry, soffset, 0x200000)
                    else:
                        yield (soffset, 0x200000)
                elif self.entry_present(entry):
                    pte_curr = entry & ~((1 << page_shift) - 1)
                    for k in range(0, ptrs_per_pae_pte):
                        pte_entry = self._read_long_long_phys(pte_curr)
                        pte_curr = pte_curr + 8
                        if self.entry_present(pte_entry):
                            if with_pte:
                                yield (pte_entry, soffset + k * 0x1000, 0x1000)
                            else:
                                yield (soffset + k * 0x1000, 0x1000)
