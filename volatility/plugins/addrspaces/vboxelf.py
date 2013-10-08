# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2005,2006,2007 4tphi Research
#
# Authors: 
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# phil@teuwen.org (Philippe Teuwen)
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

class VirtualBoxCoreDumpElf64(addrspace.AbstractRunBasedMemory):
    """ This AS supports VirtualBox ELF64 coredump format """

    order = 30

    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)

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
