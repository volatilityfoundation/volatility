# Volatility
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

# Code found in WindowsHiberFileSpace32 for parsing meta information
# is inspired by the work of Matthieu Suiche:  http://sandman.msuiche.net/.
# A special thanks to Matthieu for all his help integrating 
# this code in Volatility.

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems LLC
"""

"""Address space: windows hiberfil
   
"""

from forensics.addrspace import FileAddressSpace
import forensics.x86
from forensics.object import *
from forensics.win32.xpress import xpress_decode
from thirdparty.progressbar import *
from forensics.win32.datetime import *
from vtypes import xpsp2types as types
from forensics.x86 import IA32PagedMemory
from forensics.x86 import IA32PagedMemoryPae

page_shift = 12

hiber_types = { \
    '_IMAGE_HIBER_HEADER' : [ 0xbc, { \
    'Signature' : [ 0x0, ['array', 4,['unsigned char']]], \
    'SystemTime' : [ 0x20, ['_LARGE_INTEGER']], \
    'FirstTablePage' : [ 0x58, ['unsigned long']], \
} ], \
    'MEMORY_RANGE_ARRAY_LINK' : [ 0x10, { \
    'NextTable' : [ 0x4, ['unsigned long']], \
    'EntryCount' : [ 0xc, ['unsigned long']], \
} ], \
    'MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, { \
    'StartPage' : [ 0x4, ['unsigned long']], \
    'EndPage' : [ 0x8, ['unsigned long']], \
} ], \
    '_MEMORY_RANGE_ARRAY' : [ 0x20, { \
    'MemArrayLink' : [ 0x0, ['MEMORY_RANGE_ARRAY_LINK']], \
} ], \
  '_KGDTENTRY' : [  0x8 , { \
  'BaseLow' : [ 0x2 , ['unsigned short']], \
  'BaseMid' : [ 0x4, ['unsigned char']], \
  'BaseHigh' : [ 0x7, ['unsigned char']], \
} ], \
'_IMAGE_XPRESS_HEADER' : [  0x20 , { \
  'u09' : [ 0x9, ['unsigned char']], \
  'u0A' : [ 0xA, ['unsigned char']], \
  'u0B' : [ 0xB, ['unsigned char']], \
} ], \
}

class WindowsHiberFileSpace32:
    def __init__(self, baseAddressSpace,offset,ramsize=0,fast=False):
        self.runs = []
        self.offset = offset
        self.base = baseAddressSpace
        self.PagesListHead = {}
        self.PageDict = {}
        self.MemRangeCnt = 1
        self.HighestPage = 0
        self.PageIndex = 0
        self.AddressList = []
        self.DataCache = {}
        self.LookupCache = {}
        self.CacheHits = 0
        self.max_decode_time = 0


        # Extract header information
        self.hiber_header = self.base.read(offset, \
            obj_size(hiber_types, '_IMAGE_HIBER_HEADER'))

        self.Signature = self.base.read(offset,4)

        FirstTablePage = read_obj(self.base, hiber_types,
	    ['_IMAGE_HIBER_HEADER', 'FirstTablePage'], self.offset)

        (system_time_offset, tmp) = get_obj_offset(hiber_types, \
            ['_IMAGE_HIBER_HEADER', 'SystemTime'])
        system_time     = read_time(self.base, types, 0 + system_time_offset)

        system_time     = windows_to_unix_time(system_time)

        if system_time is None:
            self.SystemTime = "UNKNOWN"
        else:
            self.SystemTime = self.format_time(system_time)   

        # Extract processor state

        self.ProcStateOffset = 2 * 4096
        
        self.CR0 = read_obj(self.base, types,
	  ['_KPROCESSOR_STATE', 'SpecialRegisters','Cr0'], \
          self.ProcStateOffset)
        self.CR3 = read_obj(self.base, types,
	  ['_KPROCESSOR_STATE', 'SpecialRegisters','Cr3'],  \
          self.ProcStateOffset)
        self.CR4 = read_obj(self.base, types, 
	  ['_KPROCESSOR_STATE', 'SpecialRegisters','Cr4'], \
          self.ProcStateOffset)


        if fast == True:
            return

        XpressIndex = 0    
        XpressHeaderOffset = (FirstTablePage+1) * 4096
        XpressBlockSize = self.get_xpress_block_size(hiber_types, \
            XpressHeaderOffset)

        MemoryArrayOffset = FirstTablePage * 4096

        while MemoryArrayOffset:

            EntryCount = read_obj(self.base, hiber_types, \
	        ['_MEMORY_RANGE_ARRAY', 'MemArrayLink','EntryCount'], \
                MemoryArrayOffset)
            for i in range(0,EntryCount):
                MemoryArrayRangeEntryOffset = MemoryArrayOffset + \
                    0x10 + (i*0x10)
                EndPage = read_obj(self.base, hiber_types,
	           ['MEMORY_RANGE_ARRAY_RANGE', 'EndPage'], \
                   MemoryArrayRangeEntryOffset)
                StartPage = read_obj(self.base, hiber_types,
	           ['MEMORY_RANGE_ARRAY_RANGE', 'StartPage'], \
                   MemoryArrayRangeEntryOffset)

                if EndPage > self.HighestPage:
                    self.HighestPage = EndPage

                LocalPageCnt = EndPage - StartPage

                self.AddressList.append([StartPage * 0x1000, \
                    LocalPageCnt * 0x1000])

                for j in range(0,LocalPageCnt):

                    if (XpressIndex and ((XpressIndex % 0x10) == 0)):
                        XpressHeaderOffset,XpressBlockSize = \
			   self.next_xpress(hiber_types, \
                           XpressHeaderOffset)

                    PageNumber = StartPage + j
                    XpressPage = XpressIndex % 0x10

                    if XpressHeaderOffset not in self.PageDict:
                        self.PageDict[XpressHeaderOffset] = \
                            [(PageNumber,XpressBlockSize,XpressPage)]
                        self.LookupCache[PageNumber] = (XpressHeaderOffset,XpressBlockSize,XpressPage)
                    else:
                        self.PageDict[XpressHeaderOffset].append((PageNumber, \
                            XpressBlockSize, XpressPage))
                        self.LookupCache[PageNumber] = (XpressHeaderOffset,XpressBlockSize,XpressPage)

                    self.PageIndex += 1
                    XpressIndex += 1

            NextTable = read_obj(self.base, hiber_types,
	           ['_MEMORY_RANGE_ARRAY', 'MemArrayLink','NextTable'], \
                   MemoryArrayOffset)

            if ((NextTable != 0) and (EntryCount == 0xFF)):
        
                MemoryArrayOffset = NextTable * 0x1000
                self.MemRangeCnt+=1
                XpressHeaderOffset,XpressBlockSize = \
                    self.next_xpress(hiber_types,XpressHeaderOffset)
                XpressIndex = 0
            else:
                MemoryArrayOffset = 0

    def format_time(self,time):
        ts=strftime("%a %b %d %H:%M:%S %Y",
            gmtime(time))
        return ts

    def convert_to_raw(self,ofile):

        nb = len(self.PageDict)
        num_pages = self.get_number_of_pages()
        widgets = ['Convert: ', Percentage(), ' ', \
            Bar(marker=RotatingMarker()),' ', ETA()]
        pbar = ProgressBar(widgets=widgets, maxval=num_pages).start()

        page_count = 0
        for i,xb in enumerate(self.PageDict.keys()):
            nb = len(self.PageDict)
            size = self.PageDict[xb][0][1]
            data_z = self.base.read(xb+0x20,size)
            if size == 0x10000:
                data_uz = data_z
            else:
                data_uz = xpress_decode(data_z)
            for page,size,offset in self.PageDict[xb]:
                pbar.update(page_count)
                ofile.seek(page*0x1000)
                ofile.write(data_uz[offset*0x1000:offset*0x1000+0x1000])
                page_count+=1

            del data_z,data_uz
        pbar.finish() 


    def next_xpress(self, types, XpressHeader):
        XpressBlockSize = self.get_xpress_block_size(types,XpressHeader)
        XpressHeader += XpressBlockSize + obj_size(types,'_IMAGE_XPRESS_HEADER')

        Magic = self.base.read(XpressHeader, 8)
        while Magic != "\x81\x81xpress":
            XpressHeader += 8
            Magic = self.base.read(XpressHeader, 8)
            if not Magic: return None,None
        XpressBlockSize = self.get_xpress_block_size(types,XpressHeader)

        return XpressHeader,XpressBlockSize 

    def get_xpress_block_size(self,types,offset):

        u0B = read_obj(self.base, types,
	           ['_IMAGE_XPRESS_HEADER', 'u0B'], offset) << 24
        u0A = read_obj(self.base, types,
	           ['_IMAGE_XPRESS_HEADER', 'u0A'], offset) << 16
        u09 = read_obj(self.base, types,
	           ['_IMAGE_XPRESS_HEADER', 'u09'], offset) << 8
        Size = u0B + u0A + u09
        Size = Size >> 10
        Size = Size + 1

        if ((Size % 8) == 0):
            return Size
        return (Size & ~7) + 8

    def get_header(self):
        return self.hiber_header

    def get_base(self):
        return self.base

    def get_signature(self):
        return self.Signature

    def get_system_time(self):
        return self.SystemTime

    def is_paging(self):
        return (self.CR0 >> 31) & 1

    def is_pse(self):
        return (self.CR4 >> 4) & 1

    def is_pae(self):
        return (self.CR4 >> 5) & 1

    def get_number_of_memranges(self):
        return self.MemRangeCnt

    def get_number_of_pages(self):
        return self.PageIndex

    def get_addr(self, addr):
        page_offset = (addr & 0x00000FFF)
        page = addr >> page_shift
        if page in self.LookupCache:
            (hoffset,size,pageoffset) = self.LookupCache[page]
            return hoffset	
        return None

    def get_block_offset(self,xb,addr):
        page = addr >> page_shift
        if page in self.LookupCache:
            (hoffset,size,pageoffset) = self.LookupCache[page]
            return pageoffset	
        return None                
        
    def is_valid_address(self, addr):
        if self.get_addr(addr) == None:
            return False
        return True

    def read_xpress(self,baddr,BlockSize):
        if not baddr in self.DataCache:
            data_read = self.base.read(baddr,BlockSize)
            if BlockSize == 0x10000:
                data_uz = data_read
            else:
                data_uz = xpress_decode(data_read)

            self.DataCache[baddr] = data_uz
        else:
            self.CacheHits += 1
            data_uz = self.DataCache[baddr]
        return data_uz

    def read(self, addr, len):
        page_offset = (addr & 0x00000FFF)
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((len + (addr % 0x1000)) / 0x1000) - 1
        left_over = (len + addr) % 0x1000

        ImageXpressHeader = self.get_addr(addr)
        if ImageXpressHeader == None:
            return None

        BlockSize = self.get_xpress_block_size(hiber_types,ImageXpressHeader)

        baddr = ImageXpressHeader + \
                        obj_size(hiber_types,'_IMAGE_XPRESS_HEADER')	
 
        if len < first_block:
            data_uz = self.read_xpress(baddr,BlockSize)

            block_offset = self.get_block_offset(ImageXpressHeader,addr)
            return data_uz[(block_offset*0x1000+page_offset):(block_offset*0x1000+page_offset+len)]

        data_uz = self.read_xpress(baddr,BlockSize)
            
        block_offset = self.get_block_offset(ImageXpressHeader,addr)
        stuff_read = data_uz[(block_offset*0x1000+page_offset):(block_offset*0x1000+page_offset+first_block)]

        new_addr = addr + first_block

        for i in range(0,full_blocks):
            ImageXpressHeader = self.get_addr(new_addr)
            if ImageXpressHeader == None:
                return None

            BlockSize = self.get_xpress_block_size(hiber_types, \
                ImageXpressHeader)
            baddr = ImageXpressHeader + \
                obj_size(hiber_types,'_IMAGE_XPRESS_HEADER')

            data_uz = self.read_xpress(baddr,BlockSize)

            block_offset = self.get_block_offset(ImageXpressHeader,addr)
            stuff_read =  stuff_read + data_uz[(block_offset*0x1000):(block_offset*0x1000+0x1000)]
            new_addr = new_addr + 0x1000
	
        if left_over > 0:
            ImageXpressHeader = self.get_addr(new_addr)
            if ImageXpressHeader == None:
                return None
           
            BlockSize = self.get_xpress_block_size(hiber_types, \
                ImageXpressHeader)
            baddr = ImageXpressHeader + \
                obj_size(hiber_types,'_IMAGE_XPRESS_HEADER')

            data_uz = self.read_xpress(baddr,BlockSize)
            
            block_offset = self.get_block_offset(ImageXpressHeader,addr)
            stuff_read =  stuff_read + data_uz[(block_offset*0x1000):(block_offset*0x1000+left_over)] 

        return stuff_read    


    def zread(self, addr, len):
        page_offset = (addr & 0x00000FFF)
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((len + (addr % 0x1000)) / 0x1000) - 1
        left_over = (len + addr) % 0x1000

        self.check_address_range(addr)

        ImageXpressHeader = self.get_addr(addr)
        if ImageXpressHeader == None:
            if len < first_block:
                return ('\0' * len)
            stuff_read = ('\0' * first_block) 
        else:
            if len < first_block:
                return self.read(addr, len)
            stuff_read = self.read(addr, first_block)
       
        new_addr = addr + first_block

        for i in range(0,full_blocks):
            ImageXpressHeader = self.get_addr(new_addr)
            if ImageXpressHeader == None:
                stuff_read = stuff_read + ('\0' * 0x1000)
            else:
                stuff_read = stuff_read + self.read(new_addr, 0x1000)
            new_addr = new_addr + 0x1000
	

        if left_over > 0:
            ImageXpressHeader = self.get_addr(new_addr)
            if ImageXpressHeader == None:
                stuff_read = stuff_read + ('\0' * left_over)
            else:
                stuff_read = stuff_read + self.read(new_addr, left_over)

        return stuff_read    

    def read_long(self, addr):
        baseaddr = self.get_addr(addr)
        string = self.read(addr, 4)
        (longval, ) = struct.unpack('=L', string)
        return longval

    def get_available_pages(self):
        page_list = []
        for i,xb in enumerate(self.PageDict.keys()):
            for page,size,offset in self.PageDict[xb]:
                page_list.append([page*0x1000, 0x1000])
        return page_list

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
        size = self.HighestPage*0x1000+0x1000
        return [0,size]

    def check_address_range(self,addr):
        memrange = self.get_address_range()
        if addr < memrange[0] or addr > memrange[1]:
            raise IOError

    def get_available_addresses(self):
        """ This returns the ranges  of valid addresses """
        return self.AddressList

    def close(self):
        self.base.close()

    def get_version(self):

        if self.is_pae() == 1:
            addr_space = IA32PagedMemoryPae(self,self.CR3)
        else:
            addr_space = IA32PagedMemory(self,self.CR3)

        if addr_space == None:
            return (None,None,None)

        GdtIndex = (0x3B >> 3)
        GdtrBase = read_obj(self.base, types,
	     ['_KPROCESSOR_STATE', 'SpecialRegisters','Gdtr','Base'], \
             self.ProcStateOffset)

        NtTibAddr = GdtrBase + GdtIndex * obj_size(hiber_types,'_KGDTENTRY')

        BaseLow = read_obj(addr_space, hiber_types,
	     ['_KGDTENTRY','BaseLow'], NtTibAddr)

        BaseMid = read_obj(addr_space, hiber_types,
	     ['_KGDTENTRY','BaseMid'], NtTibAddr)

        BaseHigh = read_obj(addr_space, hiber_types,
	     ['_KGDTENTRY','BaseHigh'], NtTibAddr)

        NtTibAddress = (BaseLow) | (BaseMid << (2 * 8)) | (BaseHigh << (3 * 8));

        if ((NtTibAddress == 0) or (NtTibAddress > 0x80000000)):
            return (None,None,None)

        ProcessEnvironmentBlock =  read_obj(addr_space, types,
	     ['_TEB', 'ProcessEnvironmentBlock'], NtTibAddress)

        OSMajorVersion = read_obj(addr_space, types,
	     ['_PEB', 'OSMajorVersion'], ProcessEnvironmentBlock)

        OSMinorVersion = read_obj(addr_space, types,
	     ['_PEB','OSMinorVersion'], ProcessEnvironmentBlock)

        OSBuildNumber = read_obj(addr_space, types,
	     ['_PEB','OSBuildNumber'],ProcessEnvironmentBlock)

        return (OSMajorVersion,OSMinorVersion,OSBuildNumber)
