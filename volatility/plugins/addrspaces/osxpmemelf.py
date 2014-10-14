# Volatility
# Copyright (C) 2007-2014 Volatility Foundation
#
# Authors: 
# phil@teuwen.org (Philippe Teuwen)
# espen@mrfjo.org (Espen Fjellvaer Olsen)
# justincapella@gmail.com (Justin Capella)
# michael.ligh@mnin.org (Michael Ligh)
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
# References:
# VirtualBox core format: 
#     http://www.virtualbox.org/manual/ch12.html#guestcoreformat
#     http://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/dbgfcorefmt.h
#     http://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR3/DBGFCoreWrite.cpp

import volatility.obj as obj
import volatility.addrspace as addrspace

#pylint: disable-msg=C0111

class OSXPmemELF(addrspace.AbstractRunBasedMemory):
    """ This AS supports VirtualBox ELF64 coredump format """

    order = 90

    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)

        ## Quick test (before instantiating an object) 
        ## for ELF64, little-endian - ELFCLASS64 and ELFDATA2LSB
        ## for ELF32, little-endian - ELFCLASS32 and ELFDATA2LSB
        self.as_assert(base.read(0, 6) in ['\x7fELF\x02\x01', '\x7fELF\x01\x01'], "ELF Header signature invalid")

        ## Base AS should be a file AS
        elf = obj.Object("elf_hdr", offset = 0, vm = base)

        ## The PT_NOTE core descriptor structure 
        self.header = None

        for phdr in elf.program_headers():

            # Only keep load segments with valid file sizes
            if (str(phdr.p_type) != 'PT_LOAD' or
                    phdr.p_filesz == 0 or
                    phdr.p_filesz != phdr.p_memsz):
                continue

            self.runs.append((int(phdr.p_paddr),
                              int(phdr.p_offset),
                              int(phdr.p_memsz)))

        self.as_assert(len(self.runs) > 0, "No PT_LOAD segments found")


