# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2005,2006,2007 4tphi Research
#
# Authors: 
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# phil@teuwen.org (Philippe Teuwen)
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
# References:
# VirtualBox core format: 
#     http://www.virtualbox.org/manual/ch12.html#guestcoreformat
#     http://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/dbgfcorefmt.h
#     http://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR3/DBGFCoreWrite.cpp

import volatility.obj as obj
import volatility.addrspace as addrspace

#pylint: disable-msg=C0111

NT_VBOXCORE = 0xb00
NT_VBOXCPU = 0xb01
DBGFCORE_MAGIC = 0xc01ac0de
DBGFCORE_FMT_VERSION = 0x00010000

class DBGFCOREDESCRIPTOR(obj.CType):
    """A class for VBox core dump descriptors"""

    @property
    def Major(self):
        return (self.u32VBoxVersion >> 24) & 0xFF

    @property
    def Minor(self):
        return (self.u32VBoxVersion >> 16) & 0xFF

    @property
    def Build(self):
        return self.u32VBoxVersion & 0xFFFF

class VirtualBoxModification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
            'DBGFCOREDESCRIPTOR' : [ 24, {
                'u32Magic' : [ 0, ['unsigned int']],
                'u32FmtVersion' : [ 4, ['unsigned int']],
                'cbSelf' : [ 8, ['unsigned int']],
                'u32VBoxVersion' : [ 12, ['unsigned int']],
                'u32VBoxRevision' : [ 16, ['unsigned int']],
                'cCpus' : [ 20, ['unsigned int']],
            }]})
        profile.object_classes.update({'DBGFCOREDESCRIPTOR': DBGFCOREDESCRIPTOR})

class VirtualBoxCoreDumpElf64(addrspace.BaseAddressSpace):
    """ This AS supports VirtualBox ELF64 coredump format """

    order = 30

    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)

        ## Quick test (before instantiating an object) 
        ## for ELF64, little-endian - ELFCLASS64 and ELFDATA2LSB
        self.as_assert(base.read(0, 6) == '\x7fELF\x02\x01',
                       "ELF64 Header signature invalid")

        ## Base AS should be a file AS
        elf = obj.Object("elf64_hdr", offset = 0, vm = base)

        ## Make sure its a core dump
        self.as_assert(str(elf.e_type) == 'ET_CORE',
                       "ELF64 type is not a Core file")

        ## Tuple of (physical memory address, file offset, length)
        self.runs = []

        ## The PT_NOTE core descriptor structure 
        self.header = None

        for phdr in elf.program_headers():

            ## The first note should be the VBCORE segment 
            if str(phdr.p_type) == 'PT_NOTE':
                note = phdr.p_offset.dereference_as("elf64_note")

                if note.namesz == 'VBCORE' and note.n_type == NT_VBOXCORE:
                    self.header = note.cast_descsz("DBGFCOREDESCRIPTOR")
                continue

            # Only keep load segments with valid file sizes
            if (str(phdr.p_type) != 'PT_LOAD' or
                    phdr.p_filesz == 0 or
                    phdr.p_filesz != phdr.p_memsz):
                continue

            self.runs.append((int(phdr.p_paddr),
                              int(phdr.p_offset),
                              int(phdr.p_memsz)))

        self.as_assert(self.header, 'ELF error: did not find any PT_NOTE segment with VBCORE')
        self.as_assert(self.header.u32Magic == DBGFCORE_MAGIC, 'Could not find VBox core magic signature')
        self.as_assert(self.header.u32FmtVersion == DBGFCORE_FMT_VERSION, 'Unknown VBox core format version')
        self.as_assert(self.runs, 'ELF error: did not find any LOAD segment with main RAM')

    #===============================================================
    ## FIXME: everything below can be abstract - shared with vmware
    #===============================================================

    def get_header(self):
        """Get the DBGFCOREDESCRIPTOR, used by vboxinfo plugin"""
        return self.header

    def get_runs(self):
        """Get the memory block info, used by vboxinfo plugin"""
        return self.runs

    def get_addr(self, addr):
        """Find the offset in the ELF64 file were a physical 
        memory address can be found.
        
        @param addr: a physical address
        """
        for phys_addr, file_offset, length in self.runs:
            if addr >= phys_addr and addr < phys_addr + length:
                return file_offset + (addr - phys_addr)

        return None

    def is_valid_address(self, phys_addr):
        """Check if a physical address is in the file.
        
        @param phys_addr: a physical address
        """
        return self.get_addr(phys_addr) is not None

    def get_available_pages(self):
        page_list = []
        for phys_addr, length in self.get_available_addresses():
            start = phys_addr
            for page in range(start, start + length):
                page_list.append([page * 0x1000, 0x1000])
        return page_list

    def get_available_addresses(self):
        """Get a list of physical memory runs"""
        
        ## The first (and possibly the only) main memory run 
        first_run_addr, _, first_run_size = self.runs[0]
        yield (first_run_addr, first_run_size)
        
        ## If a system has more than 3.5 GB RAM, it will be 
        ## split into multiple runs due to the VGA device mem
        ## constant VBE_DISPI_LFB_PHYSICAL_ADDRESS 0xE0000000. 
        if first_run_size == 0xE0000000:
            for run_addr, _, run_size in self.runs[1:]:
                ## not all segments above 0xE0000000 are main 
                ## memory, try to skip those that are not. 
                if run_addr >= 0x100000000:
                    yield (run_addr, run_size)

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
        (physical_address, _, length) = self.runs[-1]
        size = physical_address + length
        return [0, size]

    #===============================================================
    ## FIXME: everything below can be abstract - copied from crash
    #===============================================================

    def read(self, addr, length):
        """Read data. 
        
        @param addr: the physical memory base address
        @param length: number of bytes to read from phys_addr
        """
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((length + (addr % 0x1000)) / 0x1000) - 1
        left_over = (length + addr) % 0x1000

        baddr = self.get_addr(addr)
        if baddr == None:
            return obj.NoneObject("Could not get base address at " + str(addr))

        if length < first_block:
            stuff_read = self.base.read(baddr, length)
            return stuff_read

        stuff_read = self.base.read(baddr, first_block)
        new_addr = addr + first_block
        for _i in range(0, full_blocks):
            baddr = self.get_addr(new_addr)
            if baddr == None:
                return obj.NoneObject("Could not get base address at " + str(new_addr))
            stuff_read = stuff_read + self.base.read(baddr, 0x1000)
            new_addr = new_addr + 0x1000

        if left_over > 0:
            baddr = self.get_addr(new_addr)
            if baddr == None:
                return obj.NoneObject("Could not get base address at " + str(new_addr))
            stuff_read = stuff_read + self.base.read(baddr, left_over)

        return stuff_read

    def check_address_range(self, addr):
        memrange = self.get_address_range()
        if addr < memrange[0] or addr > memrange[1]:
            raise IOError

    def zread(self, addr, length):
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((length + (addr % 0x1000)) / 0x1000) - 1
        left_over = (length + addr) % 0x1000

        self.check_address_range(addr)

        baddr = self.get_addr(addr)

        if baddr == None:
            if length < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block)
        else:
            if length < first_block:
                return self.base.read(baddr, length)
            stuff_read = self.base.read(baddr, first_block)

        new_addr = addr + first_block
        for _i in range(0, full_blocks):
            baddr = self.get_addr(new_addr)
            if baddr == None:
                stuff_read = stuff_read + ('\0' * 0x1000)
            else:
                stuff_read = stuff_read + self.base.read(baddr, 0x1000)

            new_addr = new_addr + 0x1000

        if left_over > 0:
            baddr = self.get_addr(new_addr)
            if baddr == None:
                stuff_read = stuff_read + ('\0' * left_over)
            else:
                stuff_read = stuff_read + self.base.read(baddr, left_over)
        return stuff_read
