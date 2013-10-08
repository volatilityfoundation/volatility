# Volatility
# Copyright (C) 2009-2013 Volatility Foundation
# Copyright (C) Mike Auty <mike.auty@gmail.com>
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

import os
import volatility.obj as obj
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.plugins.imagecopy as imagecopy

class Raw2dmp(imagecopy.ImageCopy):
    """Converts a physical memory sample to a windbg crash dump"""

    def calculate(self):

        blocksize = self._config.BLOCKSIZE
        self._config.WRITE = True
        pspace = utils.load_as(self._config, astype = 'physical')
        vspace = utils.load_as(self._config)

        memory_model = pspace.profile.metadata.get('memory_model', '32bit')

        if memory_model == "64bit":
            header_format = '_DMP_HEADER64'
        else:
            header_format = '_DMP_HEADER'

        headerlen = pspace.profile.get_obj_size(header_format)
        headerspace = addrspace.BufferAddressSpace(self._config, 0, "PAGE" * (headerlen / 4))
        header = obj.Object(header_format, offset = 0, vm = headerspace)

        kuser = obj.Object("_KUSER_SHARED_DATA",
                          offset = obj.VolMagic(vspace).KUSER_SHARED_DATA.v(),
                          vm = vspace)
        kdbg = obj.Object("_KDDEBUGGER_DATA64",
                          offset = obj.VolMagic(vspace).KDBG.v(),
                          vm = vspace)

        # Scanning the memory region near KDDEBUGGER_DATA64 for 
        # DBGKD_GET_VERSION64
        dbgkd = kdbg.dbgkd_version64()

        # Set the correct file magic
        for i in range(len("PAGE")):
            header.Signature[i] = [ ord(x) for x in "PAGE"][i]

        # Write the KeDebuggerDataBlock and ValidDump headers
        dumptext = "DUMP"
        header.KdDebuggerDataBlock = kdbg.obj_offset
        if memory_model == "64bit":
            dumptext = "DU64"
            header.KdDebuggerDataBlock = kdbg.obj_offset | 0xFFFF000000000000
        for i in range(len(dumptext)):
            header.ValidDump[i] = ord(dumptext[i])

        # The PaeEnabled member is essential for x86 crash files
        if memory_model == "32bit":
            if hasattr(vspace, "pae") and vspace.pae == True:
                header.PaeEnabled = 0x1
            else:
                header.PaeEnabled = 0x0

        # Set members of the crash header
        header.MajorVersion = dbgkd.MajorVersion
        header.MinorVersion = dbgkd.MinorVersion
        header.DirectoryTableBase = vspace.dtb
        header.PfnDataBase = kdbg.MmPfnDatabase
        header.PsLoadedModuleList = kdbg.PsLoadedModuleList
        header.PsActiveProcessHead = kdbg.PsActiveProcessHead
        header.MachineImageType = dbgkd.MachineType

        # Find the number of processors 
        header.NumberProcessors = len(list(kdbg.kpcrs()))

        # In MS crash dumps, SystemTime will not be set. It will 
        # represent the "Debug session time:".  We are 
        # using the member to represent the time the sample was
        # collected. 
        header.SystemTime = kuser.SystemTime.as_windows_timestamp()

        # Zero out the BugCheck members
        header.BugCheckCode = 0x00000000
        header.BugCheckCodeParameter[0] = 0x00000000
        header.BugCheckCodeParameter[1] = 0x00000000
        header.BugCheckCodeParameter[2] = 0x00000000
        header.BugCheckCodeParameter[3] = 0x00000000

        # Set the sample run information. We used to take the sum of the size 
        # of all runs, but that assumed the base layer was raw. In the case 
        # of base layers such as ELF64 core dump or any other run-based address 
        # space that may have holes for device memory, that would fail because
        # any runs after the first hole would then be at the wrong offset.
        last_run = list(pspace.get_available_addresses())[-1]
        num_pages = (last_run[0] + last_run[1]) / 0x1000
            
        header.PhysicalMemoryBlockBuffer.NumberOfRuns = 0x00000001
        header.PhysicalMemoryBlockBuffer.NumberOfPages = num_pages
        header.PhysicalMemoryBlockBuffer.Run[0].BasePage = 0x0000000000000000
        header.PhysicalMemoryBlockBuffer.Run[0].PageCount = num_pages
        header.RequiredDumpSpace = (num_pages + 2) * 0x1000

        # Zero out the remaining non-essential fields
        ContextRecordOffset = headerspace.profile.get_obj_offset(header_format, "ContextRecord")
        ExceptionOffset = headerspace.profile.get_obj_offset(header_format, "Exception")
        headerspace.write(ContextRecordOffset, "\x00" * (ExceptionOffset - ContextRecordOffset))

        # Set the "converted" comment
        CommentOffset = headerspace.profile.get_obj_offset(header_format, "Comment")
        headerspace.write(CommentOffset, "File was converted with Volatility" + "\x00")

        # Yield the header
        yield 0, headerspace.read(0, headerlen)
    
        # Write the main body
        for s, l in pspace.get_available_addresses():
            for i in range(s, s + l, blocksize):
                yield i + headerlen, pspace.read(i, min(blocksize, s + l - i))

        # Reset the config so volatility opens the crash dump 
        self._config.LOCATION = "file://" + self._config.OUTPUT_IMAGE

        # Crash virtual space 
        crash_vspace = utils.load_as(self._config)

        # The KDBG in the new crash dump
        crash_kdbg = obj.Object("_KDDEBUGGER_DATA64",
                          offset = obj.VolMagic(crash_vspace).KDBG.v(),
                          vm = crash_vspace)

        # The KPCR for the first CPU 
        kpcr = list(crash_kdbg.kpcrs())[0]
        
        # Set the CPU CONTEXT properly for the architecure 
        if memory_model == "32bit":
            kpcr.PrcbData.ProcessorState.ContextFrame.SegGs = 0x00
            kpcr.PrcbData.ProcessorState.ContextFrame.SegCs = 0x08
            kpcr.PrcbData.ProcessorState.ContextFrame.SegDs = 0x23
            kpcr.PrcbData.ProcessorState.ContextFrame.SegEs = 0x23
            kpcr.PrcbData.ProcessorState.ContextFrame.SegFs = 0x30
            kpcr.PrcbData.ProcessorState.ContextFrame.SegSs = 0x10
        else:
            kpcr.Prcb.ProcessorState.ContextFrame.SegGs = 0x00
            kpcr.Prcb.ProcessorState.ContextFrame.SegCs = 0x18
            kpcr.Prcb.ProcessorState.ContextFrame.SegDs = 0x2b
            kpcr.Prcb.ProcessorState.ContextFrame.SegEs = 0x2b
            kpcr.Prcb.ProcessorState.ContextFrame.SegFs = 0x53
            kpcr.Prcb.ProcessorState.ContextFrame.SegSs = 0x18   



        
