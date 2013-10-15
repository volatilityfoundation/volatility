# Volatility
# Copyright (C) 2012-13 Volatility Foundation
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
# Notwithstanding any rights to use the Software granted by the foregoing,
# if entities or individuals have received a Cease & Desist letter from
# the Volatility Project, the Volatility Foundation, or its copyright holders
# for violating the terms of the GPL version 2, those entities (their employees,
# subcontractors, independent contractors, and affiliates) and / or persons
# are granted no such rights and any use by any one or more of them is
# expressly prohibited, in accordance with Section 4 of the GPL version 2.
# Any rights granted to such entities and / or persons by earlier license
# agreements have been previously terminated as to them.

#pylint: disable-msg=C0111

import os
import re
import math
import volatility.obj as obj
import volatility.utils as utils
import volatility.debug as debug
import volatility.win32.tasks as tasks_mod
import volatility.win32.modules as modules
import volatility.plugins.common as common
import volatility.plugins.taskmods as taskmods
import json

#--------------------------------------------------------------------------------
# Constants
#--------------------------------------------------------------------------------

PAGE_SIZE = 0x1000
PAGE_MASK = PAGE_SIZE - 1
IMAGE_EXT = "img"
DATA_EXT = "dat"
FILEOFFSET_MASK = 0xFFFFFFFFFFFF0000
VACB_BLOCK = 0x40000
VACB_ARRAY = 0x80
VACB_OFFSET_SHIFT = 18
VACB_LEVEL_SHIFT = 7
VACB_SIZE_OF_FIRST_LEVEL = 1 << (VACB_OFFSET_SHIFT + VACB_LEVEL_SHIFT)

class _CONTROL_AREA(obj.CType):

    def extract_ca_file(self, unsafe = False):
        """ Extracts a file from a specified CONTROL_AREA

        Attempts to extract the memory resident pages pertaining to a
        particular CONTROL_AREA object.

        Args:
            control_area: Instance of a CONTROL_AREA object
            unsafe: Relax safety constraints for more data

        Returns:
            mdata: List of pages, (physoffset, fileoffset, size) tuples, that are memory resident
            zpad: List of pages, (offset, size) tuples, that not memory resident

        Raises:
        """

        zpad = []
        mdata = []

        # Depending on the particular address space being used we need to
        # determine if the MMPTE will be either 4 or 8 bytes. The x64
        # and IA32_PAE both use 8 byte PTEs. Whereas, IA32 uses 4 byte
        # PTE entries.
        memory_model = self.obj_vm.profile.metadata.get('memory_model', '32bit')
        pae = self.obj_vm.pae 

        if pae:
            mmpte_size = self.obj_vm.profile.get_obj_size("_MMPTEPA")
        else:
            mmpte_size = self.obj_vm.profile.get_obj_size("_MMPTE")

        # Calculate the size of the _CONTROL_AREA object. It is used to find
        # the correct offset for the SUBSECTION object and the size of the
        # CONTROL_AREA can differ between versions of Windows.
        control_area_size = self.size()

        # The segment is used to describe the physical view of the
        # file. We also use this as a semantic check to see if
        # the processing should continue. If the Segment address
        # is invalid, then we return.
        Segment = self.Segment
        if not Segment.is_valid():
            return mdata, zpad

        # The next semantic check validates that the _SEGMENT object
        # points back to the appropriate _CONTROL_AREA object. If the
        # check is invalid, then we return.
        if (self.obj_offset != Segment.ControlArea):
            return mdata, zpad

        # This is a semantic check added to make sure the Segment.SizeOfSegment value
        # is consistant with the Segment.TotalNumberOfPtes. This occurs fequently
        # when traversing through CONTROL_AREA Objects (~5%), often leading to
        # impossible values. Thus, to be conservative we do not proceed if the
        # Segment does not seem sound.
        if Segment.SizeOfSegment != (Segment.TotalNumberOfPtes * PAGE_SIZE):
            return mdata, zpad

        # The _SUBSECTION object is typically found immediately following
        # the CONTROL_AREA object. For Image Section Objects, the SUBSECTIONS
        # typically correspond with the sections found in the PE. On the otherhand,
        # for Data Section Objects, there is typically only a single valid SUBSECTION.
        subsection_offset = self.obj_offset + control_area_size
        #subsection = obj.Object("_SUBSECTION", subsection_offset, self.kaddr_space)
        subsection = obj.Object("_SUBSECTION", subsection_offset, self.obj_vm)

        # This was another check which was inspired by Ruud's code. It
        # verifies that the first SubsectionBaase (Mmst) never starts
        # at the beginning of a page. The UNSAFE option allows us to
        # ignore this constraint. This was necessary for dumping file data
        # for file objects found with filescan (ie $Mft)
        SubsectionBase = subsection.SubsectionBase
        if (SubsectionBase & PAGE_MASK == 0x0) and not unsafe:
            return mdata, zpad

        # We obtain the Subsections associated with this file
        # by traversing the singly linked list.  Ideally, this
        # list should be null (0) terminated. Upon occasion we
        # we have seen instances where the link pointers are
        # undefined (XXX). If we hit an invalid pointer, the we
        # we exit the traversal.
        while subsection.is_valid() and subsection.v() != 0x0:

            if not subsection:
                break

            # This constraint makes sure that the _SUBSECTION object
            # points back to the associated CONTROL_AREA object. Otherwise,
            # we exit the traversal.
            if (self.obj_offset != subsection.ControlArea):
                break

            # Extract subsection meta-data into local variables
            # this helps with performance and not having to do
            # repetitive lookups.
            PtesInSubsection = subsection.PtesInSubsection
            SubsectionBase = subsection.SubsectionBase
            NextSubsection = subsection.NextSubsection

            # The offset into the file is stored implicitely
            # based on the PTE's location within the Subsection.
            StartingSector = subsection.StartingSector
            SubsectionOffset = StartingSector * 0x200

            # This was another check based on something Ruud
            # had done.  We also so instances where DataSectionObjects
            # would hit a SubsectionBase that was paged aligned
            # and hit strange data. In those instances, the
            # MMPTE SubsectionAddress would not point to the associated
            # Subsection. (XXX)
            if (SubsectionBase & PAGE_MASK == 0x0) and not unsafe:
                break

            ptecount = 0
            while (ptecount < PtesInSubsection):

                pteoffset = SubsectionBase + (mmpte_size * ptecount)
                FileOffset = SubsectionOffset + ptecount * 0x1000

                #  The size of MMPTE changes depending on if it is IA32 (4 bytes)
                #  or IA32_PAE/AMD64 (8 bytes).
                objname = "_MMPTE"
                if pae:
                    objname = "_MMPTEPA"
                mmpte = obj.Object(objname, offset = pteoffset, vm = \
                    subsection.obj_vm)

                if not mmpte:
                    ptecount += 1
                    continue

                # First we check if the entry is valid. If the entry is valid
                # then we get the physical offset. The valid entries are actually
                # handled by the hardware.
                if mmpte.u.Hard.Valid == 0x1:

                    # There are some valid Page Table entries where bit 63
                    # is used to specify if the page is executable. This is
                    # maintained by the processor. If it is not executable,
                    # then the bit is set. Within the Intel documentation,
                    # this is known as the Execute-disable (XD) flag. Regardless,
                    # we will use the get_phys_addr method from the address space
                    # to obtain the physical address.
                    ### Should we check the size of the PAGE? Haven't seen
                    # a hit for LargePage.
                    #if mmpte.u.Hard.LargePage == 0x1:
                    #    print "LargePage"
                    physoffset = mmpte.u.Hard.PageFrameNumber << 12
                    mdata.append([physoffset, FileOffset, PAGE_SIZE])
                    ptecount += 1
                    continue

                elif mmpte.u.Soft.Prototype == 0x1:
                # If the entry is not a valid physical address then
                # we check if it contains a pointer back to the SUBSECTION
                # object. If so, the page is in the backing file and we will
                # need to pad to maintain spacial integrity of the file. This
                # check needs to be performed for looking for the transition flag.
                # The prototype PTEs are initialized as MMPTE_SUBSECTION with the
                # SubsectionAddress.

                # On x86 systems that use 4 byte MMPTE , the MMPTE_SUBSECTION
                # stores an "encoded" version of the SUBSECTION object address.
                # The data is relative to global variable (MmSubsectionBase or
                # MmNonPagedPoolEnd) depending on the WhichPool member of
                # _SUBSECTION. This applies to x86 systems running ntoskrnl.exe.
                # If bit 10 is set then it is prototype/subsection

                    if (memory_model == "32bit") and not pae:
                        SubsectionOffset = \
                          ((mmpte.u.Subsect.SubsectionAddressHigh << 7) |
                          (mmpte.u.Subsect.SubsectionAddressLow << 3))
                        #WhichPool = mmpte.u.Subsect.WhichPool
                        #print "mmpte 0x%x ptecount 0x%x sub-32 0x%x pteoffset 0x%x which 0x%x subdelta 0x%x"%(mmpte.u.Long,ptecount,subsection_offset,pteoffset,WhichPool,SubsectionOffset)
                        zpad.append([FileOffset, PAGE_SIZE])
                        ptecount += 1
                        continue

                    if memory_model == "64bit" or pae:
                        SubsectionAddress = mmpte.u.Subsect.SubsectionAddress
                    else:
                        SubsectionAddress = mmpte.u.Long

                    if SubsectionAddress == subsection.obj_offset:
                        # sub proto/prot 4c0 420
                        #print "mmpte 0x%x ptecount 0x%x sub 0x%x offset 0x%x"%(mmpte.u.Long,ptecount,SubsectionAddress,pteoffset)
                        zpad.append([FileOffset, PAGE_SIZE])
                        ptecount += 1
                        continue
                    elif (SubsectionAddress == (subsection.obj_offset + 4)):
                        # This was a special case seen on IA32_PAE systems where
                        # the SubsectionAddress pointed to subsection.obj_offset+4
                        # (0x420, 0x460, 0x4a0)

                        #print "mmpte 0x%x ptecount 0x%x sub+4 0x%x offset 0x%x"%(mmpte.u.Long,ptecount,SubsectionAddress,pteoffset)
                        zpad.append([FileOffset, PAGE_SIZE])
                        ptecount += 1
                        continue
                    else:
                        #print "mmpte 0x%x ptecount 0x%x sub_unk 0x%x offset 0x%x suboffset 0x%x"%(mmpte.u.Long,ptecount,SubsectionAddress,pteoffset,subsection.obj_offset)
                        zpad.append([FileOffset, PAGE_SIZE])
                        ptecount += 1
                        continue

                # Check if the entry is a DemandZero entry.
                elif (mmpte.u.Soft.Transition == 0x0):
                    if ((mmpte.u.Soft.PageFileLow == 0x0) and
                     (mmpte.u.Soft.PageFileHigh == 0x0)):
                        # Example entries include: a0,e0
                        #print "mmpte 0x%x ptecount 0x%x zero offset 0x%x subsec 0x%x"%(mmpte.u.Long,ptecount,pteoffset,subsection.obj_offset)
                        zpad.append([FileOffset, PAGE_SIZE])
                        ptecount += 1
                    else:
                        #print "mmpte 0x%x ptecount 0x%x paged offset 0x%x subsec 0x%x file 0x%x offset 0x%x"%(mmpte.u.Long,ptecount,pteoffset,subsection.obj_offset,mmpte.u.Soft.PageFileLow,mmpte.u.Soft.PageFileHigh)

                        zpad.append([FileOffset, PAGE_SIZE])
                        ptecount += 1

                # If the entry is not a valid physical address then
                # we also check to see if it is in transition.
                elif mmpte.u.Trans.Transition == 0x1:
                    physoffset = mmpte.u.Trans.PageFrameNumber << 12
                    #print "mmpte 0x%x ptecount 0x%x transition 0x%x offset 0x%x"%(mmpte.u.Long,ptecount,physoffset,pteoffset)

                    mdata.append([physoffset, FileOffset, PAGE_SIZE])
                    ptecount += 1
                    continue
                else:
                    # This is a catch all for all the other entry types.
                    # sub proto/pro 420,4e0,460,4a0 (x64 +0x28)(x32 +4)
                    # other a0,e0,0, (20,60)
                    # 0x80000000
                    #print "mmpte 0x%x ptecount 0x%x other offset 0x%x subsec 0x%x"%(mmpte.u.Long,ptecount,pteoffset,subsection.obj_offset)
                    zpad.append([FileOffset, PAGE_SIZE])
                    ptecount += 1

	    # Traverse the singly linked list to its next member.
            subsection = NextSubsection

        return (mdata, zpad)

class _SHARED_CACHE_MAP(obj.CType):

    def is_valid(self):
        if not obj.CType.is_valid(self):
            return False

        # Added a semantic check to make sure the data is in a sound state. It's better
        # to catch it early.
        FileSize = self.FileSize.QuadPart
        ValidDataLength = self.ValidDataLength.QuadPart
        SectionSize = self.SectionSize.QuadPart
        #print "SectionSize 0x%x < 0 or FileSize < 0x%x ValidDataLength 0x%x"%(SectionSize,FileSize,ValidDataLength)
        #if SectionSize < 0 or (FileSize < ValidDataLength):
        if SectionSize < 0 or ((FileSize < ValidDataLength) and (ValidDataLength != 0x7fffffffffffffff)):
            return False

        return True

    def process_index_array(self, array_pointer, level, limit, vacbary = None):

        """ Recursively process the sparse multilevel VACB index array

        Args:
            array_pointer:    The address of a possible index array
            shared_cache_map: The associated SHARED_CACHE_MAP object
            level:            The current level
            limit:            The level where we abandon all hope. Ideally this is 7
            vacbary:          An array of collected VACBs

        Returns:
            vacbary:          Collected VACBs 
        """
        if vacbary is None:
            vacbary = []

        if level > limit:
            return []

        # Create an array of VACB entries
        VacbArray = obj.Object("Array", offset = array_pointer, \
            vm = self.obj_vm, count = VACB_ARRAY, \
            targetType = "address", parent = self)

        # Iterate through the entries
        for _i in range(0, VACB_ARRAY):
            # Check if the VACB entry is in use
            if VacbArray[_i] == 0x0:
                continue

            Vacbs = obj.Object("_VACB", offset = int(VacbArray[_i]), vm = self.obj_vm)

            # Check if this is a valid VACB entry by verifying
            # the SharedCacheMap member.
            if Vacbs.SharedCacheMap == self.obj_offset:
                # This is a VACB associated with this cache map
                vacbinfo = self.extract_vacb(Vacbs, VACB_BLOCK)
                if vacbinfo:
                    vacbary.append(vacbinfo)
            else:
                #Process the next level of the multi-level array
                vacbary = self.process_index_array(VacbArray[_i], level + 1, limit, vacbary)
                #vacbary = vacbary + _vacbary
        return vacbary

    def extract_vacb(self, vacbs, size):
        """ Extracts data from a specified VACB

        Attempts to extract the memory resident data from a specified
        VACB.

        Args:
            vacbs: 		The VACB object
            size: 		How much data should be read from the VACB 
            shared_cache_map: 	The associated SHARED_CACHE_MAP object

        Returns:
            vacbinfo:    	Extracted VACB meta-information

        """
        # This is used to collect summary information. We will eventually leverage this
        # when creating the externally exposed APIs.
        vacbinfo = {}

        # Check if the Overlay member of _VACB is resident
        # The Overlay member stores information about the FileOffset
        # and the ActiveCount. This is just another proactive check
        # to make sure the objects are seemingly sound.
        if not vacbs.Overlay:
            return vacbinfo

        # We should add another check to make sure that
        # the SharedCacheMap member of the VACB points back
        # to the corresponding SHARED_CACHE_MAP
        if vacbs.SharedCacheMap != self.v():
            return vacbinfo

        # The FileOffset member of VACB is used to denote the
        # offset within the file where the view begins.  Since all
        # views are 256 KB in size, the bottom 16 bits are used to
        # store the number of references to the view.
        FileOffset = vacbs.Overlay.FileOffset.QuadPart

        if not FileOffset:
            return vacbinfo

        ActiveCount = vacbs.Overlay.ActiveCount
        FileOffset = FileOffset & FILEOFFSET_MASK
        BaseAddress = vacbs.BaseAddress.v()

        vacbinfo['foffset'] = int(FileOffset)
        vacbinfo['acount'] = int(ActiveCount)
        vacbinfo['voffset'] = int(vacbs.obj_offset)
        vacbinfo['baseaddr'] = int(BaseAddress)
        vacbinfo['size'] = int(size)

        return vacbinfo

    def extract_scm_file(self):
        """ Extracts a file from a specified _SHARED_CACHE_MAP

        Attempts to extract the memory resident pages pertaining to a
        particular _SHARED_CACHE_MAP object.

        Args:
            shared_cache_map: Instance of a _SHARED_CACHE_MAP object

        Returns:
            vacbary: List of collected VACB meta information.

        Raises:

        """

        vacbary = []

        if self.obj_offset == 0x0:
            return

        # Added a semantic check to make sure the data is in a sound state.
        #FileSize = shared_cache_map.FileSize.QuadPart
        #ValidDataLength = shared_cache_map.ValidDataLength.QuadPart
        SectionSize = self.SectionSize.QuadPart

        # Let's begin by determining the number of Virtual Address Control
        # Blocks (VACB) that are stored within the cache (nonpaged). A VACB
        # represents one 256-KB view in the system cache. There a are a couple
        # options to use for the data size: ValidDataLength, FileSize,
        # and SectionSize.
        full_blocks = SectionSize / VACB_BLOCK
        left_over = SectionSize % VACB_BLOCK

        # As an optimization, the shared cache map object contains a VACB index
        # array of four entries.  The VACB index arrays are arrays of pointers
        # to VACBs, that track which views of a given file are mapped in the cache.
        # For example, the first entry in the VACB index array refers to the first
        # 256 KB of the file. The InitialVacbs can describe a file up to 1 MB (4xVACB).
        iterval = 0
        while (iterval < full_blocks) and (full_blocks <= 4):
            Vacbs = self.InitialVacbs[iterval]
            vacbinfo = self.extract_vacb(Vacbs, VACB_BLOCK)
            if vacbinfo: vacbary.append(vacbinfo)
            iterval += 1

        # We also have to account for the spill over data
        # that is not found in the full blocks.  The first case to
        # consider is when the spill over is still in InitialVacbs.
        if (left_over > 0) and (full_blocks < 4):
            Vacbs = self.InitialVacbs[iterval]
            vacbinfo = self.extract_vacb(Vacbs, left_over)
            if vacbinfo: vacbary.append(vacbinfo)

        # If the file is larger than 1 MB, a seperate VACB index array
        # needs to be allocated. This is based on how many 256 KB blocks
        # would be required for the size of the file. This newly allocated
        # VACB index array is found through the Vacbs member of
        # SHARED_CACHE_MAP.

        Vacbs = self.Vacbs

        if not Vacbs or (Vacbs.v() == 0):
            return vacbary

        # There are a number of instances where the initial value in
        # InitialVacb will also be the fist entry in Vacbs. Thus we
        # ignore, since it was already processed. It is possible to just
        # process again as the file offset is specified for each VACB.
        if  self.InitialVacbs[0].obj_offset == Vacbs.v():
            return vacbary

        # If the file is less than 32 MB than it can be found in
        # a single level VACB index array.
        size_of_pointer = self.obj_vm.profile.get_obj_size("address")

        if not SectionSize > VACB_SIZE_OF_FIRST_LEVEL:

            ArrayHead = Vacbs.v()
            _i = 0
            for _i in range(0, full_blocks):
                vacb_addr = ArrayHead + (_i * size_of_pointer)
                vacb_entry = obj.Object("address", offset = vacb_addr, vm = Vacbs.obj_vm)

                # If we find a zero entry, then we proceed to the next one.
                # If the entry is zero, then the view is not mapped and we
                # skip. We do not pad because we use the FileOffset to seek
                # to the correct offset in the file.
                if not vacb_entry or (vacb_entry.v() == 0x0):
                    continue
                Vacb = obj.Object("_VACB", offset = vacb_entry.v(), vm = self.obj_vm)
                vacbinfo = self.extract_vacb(Vacb, VACB_BLOCK)
                if vacbinfo:
                    vacbary.append(vacbinfo)
            if left_over > 0:
                vacb_addr = ArrayHead + ((_i + 1) * size_of_pointer)
                vacb_entry = obj.Object("address", offset = vacb_addr, vm = Vacbs.obj_vm)

                if not vacb_entry or (vacb_entry.v() == 0x0):
                    return vacbary

                Vacb = obj.Object("_VACB", offset = vacb_entry.v(), vm = self.obj_vm)
                vacbinfo = self.extract_vacb(Vacb, left_over)
                if vacbinfo:
                    vacbary.append(vacbinfo)
            # The file is less than 32 MB, so we can
            # stop processing.
            return vacbary

        # If we get to this point, then we know that the SectionSize is greator than
        # VACB_SIZE_OF_FIRST_LEVEL (32 MB). Then we have a "sparse multilevel index
        # array where each VACB index array is made up of 128 entries. We no
        # longer assume the data is sequential. (Log2 (32 MB) - 18)/7

        #tree_depth = math.ceil((math.ceil(math.log(file_size, 2)) - 18)/7)
        level_depth = math.ceil(math.log(SectionSize, 2))
        level_depth = (level_depth - VACB_OFFSET_SHIFT) / VACB_LEVEL_SHIFT
        level_depth = math.ceil(level_depth)
        limit_depth = level_depth

        if SectionSize > VACB_SIZE_OF_FIRST_LEVEL:

            # Create an array of 128 entries for the VACB index array
            VacbArray = obj.Object("Array", offset = Vacbs.v(), \
                vm = self.obj_vm, count = VACB_ARRAY, \
                targetType = "address", parent = self)

            # We use a bit of a brute force method. We walk the
            # array and if any entry points to the shared cache map
            # object then we extract it. Otherwise, if it is non-zero
            # we attempt to traverse to the next level.
            for _i in range(0, VACB_ARRAY):
                if VacbArray[_i] == 0x0:
                    continue
                Vacb = obj.Object("_VACB", offset = int(VacbArray[_i]), vm = self.obj_vm)
                if  Vacb.SharedCacheMap == self.obj_offset:
                    vacbinfo = self.extract_vacb(Vacb, VACB_BLOCK)
                    if vacbinfo:
                        vacbary.append(vacbinfo)
                else:
                    # The Index is a pointer
                    #Process the next level of the multi-level array
                    # We set the limit_depth to be the depth of the tree
                    # as determined from the size and we initialize the
                    # current level to 2.
                    vacbary = self.process_index_array(VacbArray[_i], 2, limit_depth, vacbary)
                    #vacbary = vacbary + _vacbary

        return vacbary

class ControlAreaModification(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):
        profile.object_classes.update({
            '_CONTROL_AREA': _CONTROL_AREA,
            '_SHARED_CACHE_MAP': _SHARED_CACHE_MAP,
            })

#--------------------------------------------------------------------------------
# VTypes
#--------------------------------------------------------------------------------

# Windows x86 symbols for ntkrnlpa
ntkrnlpa_types_x86 = {
    '__ntkrnlpa' : [ 0x8, {
    'Long' : [ 0x0, ['unsigned long long']],
    'VolatileLong' : [ 0x0, ['unsigned long long']],
    'Hard' : [ 0x0, ['_MMPTE_HARDWARE_64']],
    'Flush' : [ 0x0, ['_HARDWARE_PTE']],
    'Proto' : [ 0x0, ['_MMPTE_PROTOTYPE']],
    'Soft' : [ 0x0, ['_MMPTE_SOFTWARE_64']],
    'TimeStamp' : [ 0x0, ['_MMPTE_TIMESTAMP']],
    'Trans' : [ 0x0, ['_MMPTE_TRANSITION_64']],
    'Subsect' : [ 0x0, ['_MMPTE_SUBSECTION_64']],
    'List' : [ 0x0, ['_MMPTE_LIST']],
    } ],
    '_MMPTEPA' : [ 0x8, {
    'u' : [ 0x0, ['__ntkrnlpa']],
    } ],
    '_MMPTE_SUBSECTION_64' : [ 0x8, {
    'Valid' : [ 0x0, ['BitField', dict(start_bit = 0, end_bit = 1, native_type = 'unsigned long long')]],
    'Unused0' : [ 0x0, ['BitField', dict(start_bit = 1, end_bit = 5, native_type = 'unsigned long long')]],
    'Protection' : [ 0x0, ['BitField', dict(start_bit = 5, end_bit = 10, native_type = 'unsigned long long')]],
    'Prototype' : [ 0x0, ['BitField', dict(start_bit = 10, end_bit = 11, native_type = 'unsigned long long')]],
    'Unused1' : [ 0x0, ['BitField', dict(start_bit = 11, end_bit = 32, native_type = 'unsigned long long')]],
    'SubsectionAddress' : [ 0x0, ['BitField', dict(start_bit = 32, end_bit = 64, native_type = 'long long')]],
    } ],
    '_MMPTE_TRANSITION_64' : [ 0x8, {
    'Valid' : [ 0x0, ['BitField', dict(start_bit = 0, end_bit = 1, native_type = 'unsigned long long')]],
    'Write' : [ 0x0, ['BitField', dict(start_bit = 1, end_bit = 2, native_type = 'unsigned long long')]],
    'Owner' : [ 0x0, ['BitField', dict(start_bit = 2, end_bit = 3, native_type = 'unsigned long long')]],
    'WriteThrough' : [ 0x0, ['BitField', dict(start_bit = 3, end_bit = 4, native_type = 'unsigned long long')]],
    'CacheDisable' : [ 0x0, ['BitField', dict(start_bit = 4, end_bit = 5, native_type = 'unsigned long long')]],
    'Protection' : [ 0x0, ['BitField', dict(start_bit = 5, end_bit = 10, native_type = 'unsigned long long')]],
    'Prototype' : [ 0x0, ['BitField', dict(start_bit = 10, end_bit = 11, native_type = 'unsigned long long')]],
    'Transition' : [ 0x0, ['BitField', dict(start_bit = 11, end_bit = 12, native_type = 'unsigned long long')]],
    'PageFrameNumber' : [ 0x0, ['BitField', dict(start_bit = 12, end_bit = 48, native_type = 'unsigned long long')]],
    'Unused' : [ 0x0, ['BitField', dict(start_bit = 48, end_bit = 64, native_type = 'unsigned long long')]],
    }],
   '_MMPTE_HARDWARE_64' : [ 0x8, {
    'Valid' : [ 0x0, ['BitField', dict(start_bit = 0, end_bit = 1, native_type = 'unsigned long long')]],
    'Dirty1' : [ 0x0, ['BitField', dict(start_bit = 1, end_bit = 2, native_type = 'unsigned long long')]],
    'Owner' : [ 0x0, ['BitField', dict(start_bit = 2, end_bit = 3, native_type = 'unsigned long long')]],
    'WriteThrough' : [ 0x0, ['BitField', dict(start_bit = 3, end_bit = 4, native_type = 'unsigned long long')]],
    'CacheDisable' : [ 0x0, ['BitField', dict(start_bit = 4, end_bit = 5, native_type = 'unsigned long long')]],
    'Accessed' : [ 0x0, ['BitField', dict(start_bit = 5, end_bit = 6, native_type = 'unsigned long long')]],
    'Dirty' : [ 0x0, ['BitField', dict(start_bit = 6, end_bit = 7, native_type = 'unsigned long long')]],
    'LargePage' : [ 0x0, ['BitField', dict(start_bit = 7, end_bit = 8, native_type = 'unsigned long long')]],
    'Global' : [ 0x0, ['BitField', dict(start_bit = 8, end_bit = 9, native_type = 'unsigned long long')]],
    'CopyOnWrite' : [ 0x0, ['BitField', dict(start_bit = 9, end_bit = 10, native_type = 'unsigned long long')]],
    'Unused' : [ 0x0, ['BitField', dict(start_bit = 10, end_bit = 11, native_type = 'unsigned long long')]],
    'Write' : [ 0x0, ['BitField', dict(start_bit = 11, end_bit = 12, native_type = 'unsigned long long')]],
    'PageFrameNumber' : [ 0x0, ['BitField', dict(start_bit = 12, end_bit = 48, native_type = 'unsigned long long')]],
    'reserved1' : [ 0x0, ['BitField', dict(start_bit = 48, end_bit = 52, native_type = 'unsigned long long')]],
    'SoftwareWsIndex' : [ 0x0, ['BitField', dict(start_bit = 52, end_bit = 63, native_type = 'unsigned long long')]],
    'NoExecute' : [ 0x0, ['BitField', dict(start_bit = 63, end_bit = 64, native_type = 'unsigned long long')]],
    } ],
    '_MMPTE_SOFTWARE_64' : [ 0x8, {
    'Valid' : [ 0x0, ['BitField', dict(start_bit = 0, end_bit = 1, native_type = 'unsigned long long')]],
    'PageFileLow' : [ 0x0, ['BitField', dict(start_bit = 1, end_bit = 5, native_type = 'unsigned long long')]],
    'Protection' : [ 0x0, ['BitField', dict(start_bit = 5, end_bit = 10, native_type = 'unsigned long long')]],
    'Prototype' : [ 0x0, ['BitField', dict(start_bit = 10, end_bit = 11, native_type = 'unsigned long long')]],
    'Transition' : [ 0x0, ['BitField', dict(start_bit = 11, end_bit = 12, native_type = 'unsigned long long')]],
    'UsedPageTableEntries' : [ 0x0, ['BitField', dict(start_bit = 12, end_bit = 22, native_type = 'unsigned long long')]],
    'InStore' : [ 0x0, ['BitField', dict(start_bit = 22, end_bit = 23, native_type = 'unsigned long long')]],
    'Reserved' : [ 0x0, ['BitField', dict(start_bit = 23, end_bit = 32, native_type = 'unsigned long long')]],
    'PageFileHigh' : [ 0x0, ['BitField', dict(start_bit = 32, end_bit = 64, native_type = 'unsigned long long')]],
    } ],
}

class DumpFilesVTypesx86(obj.ProfileModification):
    """This modification applies the vtypes for all 
    versions of 32bit Windows."""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x : x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(ntkrnlpa_types_x86)

class DumpFiles(common.AbstractWindowsCommand):
    """Extract memory mapped and cached files"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        self.kaddr_space = None
        self.filters = []

        config.add_option('REGEX', short_option = 'r',
                      help = 'Dump files matching REGEX',
                      action = 'store', type = 'string')
        config.add_option('IGNORE-CASE', short_option = 'i',
                      help = 'Ignore case in pattern match',
                      action = 'store_true', default = False)
        config.add_option('OFFSET', short_option = 'o', default = None,
                      help = 'Dump files for Process with physical address OFFSET',
                      action = 'store', type = 'int')
        config.add_option('PHYSOFFSET', short_option = 'Q', default = None,
                      help = 'Dump File Object at physical address PHYSOFFSET',
                      action = 'store', type = 'int')
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                      cache_invalidator = False,
                      help = 'Directory in which to dump extracted files')
        config.add_option('SUMMARY-FILE', short_option = 'S', default = None,
                      cache_invalidator = False,
                      help = 'File where to store summary information')
        config.add_option('PID', short_option = 'p', default = None,
                      help = 'Operate on these Process IDs (comma-separated)',
                      action = 'store', type = 'str')
        config.add_option('NAME', short_option = 'n',
                      help = 'Include extracted filename in output file path',
                      action = 'store_true', default = False)
        config.add_option('UNSAFE', short_option = 'u',
                      help = 'Relax safety constraints for more data',
                      action = 'store_true', default = False)

        # Possible filters include:
        # SharedCacheMap,DataSectionObject,ImageSectionObject,HandleTable,VAD
        config.add_option("FILTER", short_option = 'F', default = None,
                            help = 'Filters to apply (comma-separated)')

    def filter_tasks(self, tasks):
        """ Reduce the tasks based on the user selectable PIDS parameter.

        Returns a reduced list or the full list if config.PIDS not specified.
        """

        if self._config.PID is None:
            return tasks

        try:
            pidlist = [int(p) for p in self._config.PID.split(',')]
        except ValueError:
            debug.error("Invalid PID {0}".format(self._config.PID))

        return [t for t in tasks if t.UniqueProcessId in pidlist]

    def audited_read_bytes(self, vm, vaddr, length, pad):
        """ This function provides an audited zread capability

        It performs a similar function to zread, in that it will
        pad "invalid" pages.  The main difference is that it allows
        us to collect auditing information about which pages were actually 
        present and which ones were padded. 

        Args:
            vm: The address space to read the data from. 
            vaddr: The virtual address to start reading the data from.
            length: How many bytes to read
            pad: This argument controls if the unavailable bytes are padded.

        Returns:
            ret: Data that was read
            mdata: List of pages that are memory resident
            zpad: List of pages that not memory resident

        Raises:

        """

        zpad = []
        mdata = []

        vaddr, length = int(vaddr), int(length)

        ret = ''

        while length > 0:
            chunk_len = min(length, PAGE_SIZE - (vaddr % PAGE_SIZE))

            buf = vm.read(vaddr, chunk_len)
            if vm.vtop(vaddr) is None:
                zpad.append([vaddr, chunk_len])
                if pad:
                    buf = '\x00' * chunk_len
                else:
                    buf = ''
            else:
                mdata.append([vaddr, chunk_len])

            ret += buf
            vaddr += chunk_len
            length -= chunk_len

        return ret, mdata, zpad

    def calculate(self):
        """ Finds all the requested FILE_OBJECTS  
        
        Traverses the VAD and HandleTable to find all requested
        FILE_OBJECTS

        """
        # Initialize containers for collecting artifacts.
        control_area_list = []
        shared_maps = []
        procfiles = []

        # These lists are used for object collecting files from
        # both the VAD and handle tables
        vadfiles = []
        handlefiles = []

        # Determine which filters the user wants to see
        self.filters = []
        if self._config.FILTER:
            self.filters = self._config.FILTER.split(',')

        # Instantiate the kernel address space
        self.kaddr_space = utils.load_as(self._config)

        # Check to see if the physical address offset was passed for a
        # particular process. Otherwise, use the whole task list.
        if self._config.OFFSET != None:
            tasks_list = [taskmods.DllList.virtual_process_from_physical_offset(
                self.kaddr_space, self._config.OFFSET)]
        else:
            # Filter for the specified processes
            tasks_list = self.filter_tasks(tasks_mod.pslist(self.kaddr_space))

        # If a regex is specified, build it.
        if self._config.REGEX:
            try:
                if self._config.IGNORE_CASE:
                    file_re = re.compile(self._config.REGEX, re.I)
                else:
                    file_re = re.compile(self._config.REGEX)
            except re.error, e:
                debug.error('Error parsing regular expression: {0:s}'.format(e))

        # Check to see if a specific physical address was specified for a
        # FILE_OBJECT. In particular, this is useful for FILE_OBJECTS that
        # are found with filescan that are not associated with a process
        # For example, $Mft.
        if self._config.PHYSOFFSET:
            file_obj = obj.Object("_FILE_OBJECT", self._config.PHYSOFFSET, self.kaddr_space.base, native_vm = self.kaddr_space)
            procfiles.append((None, [file_obj]))
            #return

        # Iterate through the process list and collect all references to
        # FILE_OBJECTS from both the VAD and HandleTable. Each open handle to a file
        # has a corresponding FILE_OBJECT.
        if not self._config.PHYSOFFSET:
            for task in tasks_list:
                pid = task.UniqueProcessId

                # Extract FILE_OBJECTS from the VAD
                if not self.filters or "VAD" in self.filters:
                    for vad in task.VadRoot.traverse():
                        if vad != None:
                            try:
                                control_area = vad.ControlArea
                                if not control_area:
                                    continue
                                file_object = vad.FileObject
                                if file_object:

                                    # Filter for specific FILE_OBJECTS based on user defined
                                    # regular expression. (Performance optimization)
                                    if self._config.REGEX:
                                        name = None
                                        if file_object.FileName:
                                            name = str(file_object.file_name_with_device())
                                        if not name:
                                            continue
                                        if not file_re.search(name):
                                            continue

                                    vadfiles.append(file_object)
                            except AttributeError:
                                pass

                if not self.filters or "HandleTable" in self.filters:
                    # Extract the FILE_OBJECTS from the handle table
                    if task.ObjectTable.HandleTableList:
                        for handle in task.ObjectTable.handles():
                            otype = handle.get_object_type()
                            if otype == "File":
                                file_obj = handle.dereference_as("_FILE_OBJECT")

                                if file_obj:

                                    # Filter for specific FILE_OBJECTS based on user defined
                                    # regular expression. (Performance Optimization)
                                    if self._config.REGEX:
                                        name = None
                                        if file_obj.FileName:
                                            name = str(file_obj.file_name_with_device())
                                        if not name:
                                            continue
                                        if not file_re.search(name):
                                            continue

                                    handlefiles.append(file_obj)

                # Append the lists of file objects
                #allfiles = handlefiles + vadfiles
                procfiles.append((pid, handlefiles + vadfiles))

        for pid, allfiles in procfiles:
            for file_obj in allfiles:

                if not self._config.PHYSOFFSET:
                    offset = file_obj.obj_offset
                else:
                    offset = self._config.PHYSOFFSET

                name = None

                if file_obj.FileName:
                    name = str(file_obj.file_name_with_device())

                # The SECTION_OBJECT_POINTERS structure is used by the memory
                # manager and cache manager to store file-mapping and cache information
                # for a particular file stream. We will use it to determine what type
                # of FILE_OBJECT we have and how it should be parsed.
                if file_obj.SectionObjectPointer:
                    DataSectionObject = \
                        file_obj.SectionObjectPointer.DataSectionObject
                    SharedCacheMap = \
                        file_obj.SectionObjectPointer.SharedCacheMap
                    ImageSectionObject = \
                        file_obj.SectionObjectPointer.ImageSectionObject

                    # The ImageSectionObject is used to track state information for
                    # an executable file stream. We will use it to extract memory
                    # mapped binaries.

                    if not self.filters or "ImageSectionObject" in self.filters:

                        if ImageSectionObject and ImageSectionObject != 0:
                            summaryinfo = {}
                            # It points to a image section object( CONTROL_AREA )
                            control_area = \
                                ImageSectionObject.dereference_as('_CONTROL_AREA')

                            if not control_area in control_area_list:
                                control_area_list.append(control_area)

                                # The format of the filenames: file.<pid>.<control_area>.[img|dat]
                                ca_offset_string = "0x{0:x}".format(control_area.obj_offset)
                                if self._config.NAME and name != None:
                                    fname = name.split("\\")
                                    ca_offset_string += "." + fname[-1]
                                file_string = ".".join(["file", str(pid), ca_offset_string, IMAGE_EXT])
                                of_path = os.path.join(self._config.DUMP_DIR, file_string)
                                (mdata, zpad) = control_area.extract_ca_file(self._config.UNSAFE)
                                summaryinfo['name'] = name
                                summaryinfo['type'] = "ImageSectionObject"
                                if pid:
                                    summaryinfo['pid'] = int(pid)
                                else:
                                    summaryinfo['pid'] = None
                                summaryinfo['present'] = mdata
                                summaryinfo['pad'] = zpad
                                summaryinfo['fobj'] = int(offset)
                                summaryinfo['ofpath'] = of_path
                                yield summaryinfo

                    # The DataSectionObject is used to track state information for
                    # a data file stream. We will use it to extract artifacts of
                    # memory mapped data files.

                    if not self.filters or "DataSectionObject" in self.filters:

                        if DataSectionObject and DataSectionObject != 0:
                            summaryinfo = {}
                            # It points to a data section object (CONTROL_AREA)
                            control_area = DataSectionObject.dereference_as('_CONTROL_AREA')

                            if not control_area in control_area_list:
                                control_area_list.append(control_area)

                                # The format of the filenames: file.<pid>.<control_area>.[img|dat]
                                ca_offset_string = "0x{0:x}".format(control_area.obj_offset)
                                if self._config.NAME and name != None:
                                    fname = name.split("\\")
                                    ca_offset_string += "." + fname[-1]
                                file_string = ".".join(["file", str(pid), ca_offset_string, DATA_EXT])
                                of_path = os.path.join(self._config.DUMP_DIR, file_string)

                                (mdata, zpad) = control_area.extract_ca_file(self._config.UNSAFE)
                                summaryinfo['name'] = name
                                summaryinfo['type'] = "DataSectionObject"
                                if pid:
                                    summaryinfo['pid'] = int(pid)
                                else:
                                    summaryinfo['pid'] = None
                                summaryinfo['present'] = mdata
                                summaryinfo['pad'] = zpad
                                summaryinfo['fobj'] = int(offset)
                                summaryinfo['ofpath'] = of_path
                                yield summaryinfo

                    # The SharedCacheMap is used to track views that are mapped to the
                    # data file stream. Each cached file has a single SHARED_CACHE_MAP object,
                    # which has pointers to slots in the system cache which contain views of the file.
                    # The shared cache map is used to describe the state of the cached file.
                    if self.filters and "SharedCacheMap" not in self.filters:
                        continue

                    if SharedCacheMap:
                        vacbary = []
                        summaryinfo = {}
                        #The SharedCacheMap member points to a SHARED_CACHE_MAP object.
                        shared_cache_map = SharedCacheMap.dereference_as('_SHARED_CACHE_MAP')
                        if shared_cache_map.obj_offset == 0x0:
                            continue

                        # Added a semantic check to make sure the data is in a sound state. It's better
                        # to catch it early.
                        if not shared_cache_map.is_valid():
                            continue

                        if not shared_cache_map.obj_offset in shared_maps:
                            shared_maps.append(shared_cache_map.obj_offset)
                        else:
                            continue

                        shared_cache_map_string = ".0x{0:x}".format(shared_cache_map.obj_offset)
                        if self._config.NAME and name != None:
                            fname = name.split("\\")
                            shared_cache_map_string = shared_cache_map_string + "." + fname[-1]
                        of_path = os.path.join(self._config.DUMP_DIR, "file." + str(pid) + shared_cache_map_string + ".vacb")

                        vacbary = shared_cache_map.extract_scm_file()

                        summaryinfo['name'] = name
                        summaryinfo['type'] = "SharedCacheMap"
                        if pid:
                            summaryinfo['pid'] = int(pid)
                        else:
                            summaryinfo['pid'] = None
                        summaryinfo['fobj'] = int(offset)
                        summaryinfo['ofpath'] = of_path
                        summaryinfo['vacbary'] = vacbary
                        yield summaryinfo

    def render_text(self, outfd, data):
        """Renders output for the dumpfiles plugin. 

        This includes extracting the file artifacts from memory 
        to the specified dump directory.

        Args:
            outfd: The file descriptor to write the text to.
            data:  (summaryinfo)

        """

        # Summary file object
        summaryfo = None
        summaryinfo = data

        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        if self._config.SUMMARY_FILE:
            summaryfo = open(self._config.SUMMARY_FILE, 'wb')

        for summaryinfo in data:

            if summaryinfo['type'] == "DataSectionObject":

                outfd.write("DataSectionObject {0:#010x}   {1:<6} {2}\n".format(summaryinfo['fobj'], summaryinfo['pid'], summaryinfo['name']))
                if len(summaryinfo['present']) == 0:
                    continue

                of = open(summaryinfo['ofpath'], 'wb')

                for mdata in summaryinfo['present']:
                    rdata = None
                    if not mdata[0]:
                        continue

                    try:
                        rdata = self.kaddr_space.base.read(mdata[0], mdata[2])
                    except (IOError, OverflowError):
                        debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'], summaryinfo['name'], mdata[0], mdata[2]))

                    if not rdata:
                        continue

                    of.seek(mdata[1])
                    of.write(rdata)
                    continue
                # XXX Verify FileOffsets
                #for zpad in summaryinfo['pad']:
                #    of.seek(zpad[0])
                #    of.write("\0" * zpad[1])

                if self._config.SUMMARY_FILE:
                    json.dump(summaryinfo, summaryfo)
                of.close()

            elif summaryinfo['type'] == "ImageSectionObject":
                outfd.write("ImageSectionObject {0:#010x}   {1:<6} {2}\n".format(summaryinfo['fobj'], summaryinfo['pid'], summaryinfo['name']))

                if len(summaryinfo['present']) == 0:
                    continue

                of = open(summaryinfo['ofpath'], 'wb')

                for mdata in summaryinfo['present']:
                    rdata = None
                    if not mdata[0]:
                        continue

                    try:
                        rdata = self.kaddr_space.base.read(mdata[0], mdata[2])
                    except (IOError, OverflowError):
                        debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'], summaryinfo['name'], mdata[0], mdata[2]))

                    if not rdata:
                        continue

                    of.seek(mdata[1])
                    of.write(rdata)
                    continue

                # XXX Verify FileOffsets
                #for zpad in summaryinfo['pad']:
                #    print "ZPAD 0x%x"%(zpad[0])
                #    of.seek(zpad[0])
                #    of.write("\0" * zpad[1])

                if self._config.SUMMARY_FILE:
                    json.dump(summaryinfo, summaryfo)
                of.close()

            elif summaryinfo['type'] == "SharedCacheMap":

                outfd.write("SharedCacheMap {0:#010x}   {1:<6} {2}\n".format(summaryinfo['fobj'], summaryinfo['pid'], summaryinfo['name']))
                of = open(summaryinfo['ofpath'], 'wb')
                for vacb in summaryinfo['vacbary']:
                    if not vacb:
                        continue
                    (rdata, mdata, zpad) = self.audited_read_bytes(self.kaddr_space, vacb['baseaddr'], vacb['size'], True)
                    ### We need to update the mdata,zpad
                    if rdata:
                        try:
                            of.seek(vacb['foffset'])
                            of.write(rdata)
                        except IOError:
                            # TODO: Handle things like write errors (not enough disk space, etc)
                            continue
                    vacb['present'] = mdata
                    vacb['pad'] = zpad

                if self._config.SUMMARY_FILE:
                    json.dump(summaryinfo, summaryfo)
                of.close()

            else:
                return
        if self._config.SUMMARY_FILE:
            summaryfo.close()
