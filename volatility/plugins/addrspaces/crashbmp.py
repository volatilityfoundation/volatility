# Volatility
# Copyright (C) 2014 Volatility Foundation
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

""" An AS for processing Windows Bitmap crash dumps """
import struct
import volatility.obj as obj
import volatility.addrspace as addrspace
import volatility.plugins.addrspaces.crash as crash

#pylint: disable-msg=C0111

class BitmapDmpVTypes(obj.ProfileModification):

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == "64bit"}

    def modification(self, profile):
        profile.vtypes.update({
              '_FULL_DUMP64' : [ 0x38, {
                'Signature' : [ 0x0, ['array', 4, ['unsigned char']]],
                'ValidDump' : [ 0x4, ['array', 4, ['unsigned char']]],
                'DumpOptions' : [ 0x8, ['unsigned long long']],
                'HeaderSize' : [ 0x20, ['unsigned long long']],  
                'BitmapSize' : [ 0x28, ['unsigned long long']],  
                'Pages' : [ 0x30, ['unsigned long long']], 
                'Buffer' : [ 0x38, ['array', lambda x: (x.BitmapSize+7) / 0x8, ['unsigned char']]],
                'Buffer2' : [ 0x38, ['array', lambda x: (x.BitmapSize + 31) / 32, ['unsigned long']]],
            } ],
            })


class WindowsCrashDumpSpace64BitMap(crash.WindowsCrashDumpSpace32):
    """ This AS supports Windows BitMap Crash Dump format """
    order = 29
    dumpsig = 'PAGEDU64'
    headertype = "_DMP_HEADER64"
    headerpages = 0x13
    bitmaphdroffset = 0x2000 

    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")

        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)

        ## Must start with the magic PAGEDUMP
        self.as_assert((base.read(0, 8) == self.dumpsig), "Header signature invalid")

        self.as_assert(self.profile.has_type(self.headertype), self.headertype + " not available in profile")
        self.header = obj.Object(self.headertype, 0, base)

        # This address space supports Windows Bitmap crash dump files
        # which, based on empirical tests, have a DumpType of 0x5.  
        self.as_assert((self.header.DumpType == 5), "Unsupported dump format")

        # Instantiate the Summary/Full Bitmap header
        self.bitmaphdr = obj.Object("_FULL_DUMP64", self.bitmaphdroffset, base)

        # Create a cached version of the Header/Bitmap to reduce I/O
        fdmp_buff = base.read(self.bitmaphdroffset, self.bitmaphdr.HeaderSize-self.bitmaphdroffset)
        bufferas = addrspace.BufferAddressSpace(self._config, data = fdmp_buff)
        self.bitmaphdr2 = obj.Object('_FULL_DUMP64', vm = bufferas, offset = 0)

        firstbit = None                         # First bit in a run
        firstoffset = 0                         # File offset of first bit 
        lastbit = None                          # Last bit in a run
        lastbitseen = 0                         # Most recent bit processed
        offset = self.bitmaphdr2.HeaderSize     # Size of file headers

        for i in range(0, ((self.bitmaphdr2.BitmapSize + 31) / 32)):
            if self.bitmaphdr.Buffer2[i] == 0:
                 if firstbit != None:
                    lastbit = ((i - 1) * 32) + 31
                    self.runs.append((firstbit * 0x1000, firstoffset, (lastbit - firstbit + 1) * 0x1000))
                    firstbit = None
            elif self.bitmaphdr.Buffer2[i] == 0xFFFFFFFF:
                 if firstbit == None:
                     firstoffset = offset
                     firstbit = i * 32
                 offset = offset + (32 * 0x1000)
            else:
                 wordoffset = i * 32
                 for j in range(0, 32):
                     BitAddr = wordoffset + j 
                     ByteOffset = BitAddr >> 3
                     ByteAddress = (self.bitmaphdr2.Buffer[ByteOffset])
                     ShiftCount = (BitAddr & 0x7)
                     if ((ByteAddress >> ShiftCount) & 1):
                         if firstbit == None:
                             firstoffset = offset
                             firstbit = BitAddr
                         offset = offset + 0x1000
                     else:
                         if firstbit != None:
                             lastbit = BitAddr - 1
                             self.runs.append((firstbit * 0x1000, firstoffset, (lastbit - firstbit + 1) * 0x1000))
                             firstbit = None
            lastbitseen = (i * 32) + 31

        if firstbit != None:
            self.runs.append((firstbit * 0x1000, firstoffset, (lastbitseen - firstbit + 1) * 0x1000))

        self.dtb = self.header.DirectoryTableBase.v()
