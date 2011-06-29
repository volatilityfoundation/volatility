# Volatility
#
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
#
# Code found in WindowsHiberFileSpace32 for parsing meta information
# is inspired by the work of Matthieu Suiche:  http://sandman.msuiche.net/.
# A special thanks to Matthieu for all his help integrating 
# this code in Volatility.

""" A Hiber file Address Space """
import volatility.plugins.addrspaces.standard as standard
import volatility.obj as obj
import volatility.win32.xpress as xpress
import struct


#pylint: disable-msg=C0111

PAGE_SIZE = 0x1000
page_shift = 12

class Store(object):
    def __init__(self, limit = 50):
        self.limit = limit
        self.cache = {}
        self.seq = []
        self.size = 0

    def put(self, key, item):
        self.cache[key] = item
        self.size += len(item)

        self.seq.append(key)
        if len(self.seq) >= self.limit:
            key = self.seq.pop(0)
            self.size -= len(self.cache[key])
            del self.cache[key]

    def get(self, key):
        return self.cache[key]

class WindowsHiberFileSpace32(standard.FileAddressSpace):
    """ This is a hibernate address space for windows hibernation files.

    In order for us to work we need to:
    1) have a valid baseAddressSpace
    2) the first 4 bytes must be 'hibr'
    """
    order = 10
    def __init__(self, base, config, **kwargs):
        self.as_assert(base, "No base Address Space")
        standard.FileAddressSpace.__init__(self, base, config, layered = True, **kwargs)
        self.runs = []
        self.PageDict = {}
        self.HighestPage = 0
        self.PageIndex = 0
        self.AddressList = []
        self.LookupCache = {}
        self.PageCache = Store(50)
        self.MemRangeCnt = 0
        self.offset = 0

        # Extract header information
        self.as_assert(self.profile.has_type("_IMAGE_HIBER_HEADER"), "_IMAGE_HIBER_HEADER not available in profile")
        self.header = obj.Object('_IMAGE_HIBER_HEADER', 0, base)

        ## Is the signature right?
        if self.header.Signature.lower() not in ['hibr', 'wake']:
            self.header = obj.NoneObject("Invalid hibernation header")

        # Check it's definitely a hibernation file
        self.as_assert(self._get_first_table_page() is not None, "No xpress signature found")

        # Extract processor state
        self.ProcState = obj.Object("_KPROCESSOR_STATE", 2 * 4096, base)

        ## This is a pointer to the page table - any ASs above us dont
        ## need to search for it.
        self.dtb = self.ProcState.SpecialRegisters.Cr3.v()

        # This is a lengthy process, it was cached, but it may be best to delay this
        # until it's absolutely necessary and/or convert it into a generator...
        self.build_page_cache()

        # FIXME: Remove the cacheing code until we can do hashes and check that the 
        # data we're reading back has a chance of being right
        # 
        #if config.DEBUG:
        #    try:
        #        fd = open("/tmp/cache.bin",'rb')
        #        data = pickle.load(fd)
        #        self.PageDict , self.LookupCache = data
        #        fd.close()
        #    except (IOError, EOFError):
        #        fd = open("/tmp/cache.bin",'wb')
        #        pickle.dump((self.PageDict , self.LookupCache), fd, -1)
        #        fd.close()

    def _get_first_table_page(self):
        if self.header != None:
            return self.header.FirstTablePage
        for i in range(10):
            if self.base.read(i * PAGE_SIZE, 8) == "\x81\x81xpress":
                return i - 1
        return None

    def build_page_cache(self):
        XpressIndex = 0
        XpressHeader = obj.Object("_IMAGE_XPRESS_HEADER",
                                  (self._get_first_table_page() + 1) * 4096,
                                  self.base)

        XpressBlockSize = self.get_xpress_block_size(XpressHeader)

        MemoryArrayOffset = self._get_first_table_page() * 4096

        while MemoryArrayOffset:
            MemoryArray = obj.Object('_MEMORY_RANGE_ARRAY', MemoryArrayOffset, self.base)

            EntryCount = MemoryArray.MemArrayLink.EntryCount.v()
            for i in MemoryArray.RangeTable:
                start = i.StartPage.v()
                end = i.EndPage.v()
                LocalPageCnt = end - start

                if end > self.HighestPage:
                    self.HighestPage = end

                self.AddressList.append((start * 0x1000, LocalPageCnt * 0x1000))

                for j in range(0, LocalPageCnt):
                    if (XpressIndex and ((XpressIndex % 0x10) == 0)):
                        XpressHeader, XpressBlockSize = \
                                      self.next_xpress(XpressHeader, XpressBlockSize)

                    PageNumber = start + j
                    XpressPage = XpressIndex % 0x10
                    #print [(PageNumber,XpressBlockSize,XpressPage)]
                    if XpressHeader.obj_offset not in self.PageDict:
                        self.PageDict[XpressHeader.obj_offset] = [
                            (PageNumber, XpressBlockSize, XpressPage)]
                    else:
                        self.PageDict[XpressHeader.obj_offset].append(
                            (PageNumber, XpressBlockSize, XpressPage))

                    ## Update the lookup cache
                    self.LookupCache[PageNumber] = (
                        XpressHeader.obj_offset, XpressBlockSize, XpressPage)

                    self.PageIndex += 1
                    XpressIndex += 1

            NextTable = MemoryArray.MemArrayLink.NextTable.v()

            if (NextTable and (EntryCount == 0xFF)):
                MemoryArrayOffset = NextTable * 0x1000
                self.MemRangeCnt += 1
                XpressHeader, XpressBlockSize = \
                                             self.next_xpress(XpressHeader, XpressBlockSize)

                XpressIndex = 0
            else:
                MemoryArrayOffset = 0

    def convert_to_raw(self, ofile):
        page_count = 0
        for _i, xb in enumerate(self.PageDict.keys()):
            size = self.PageDict[xb][0][1]
            data_z = self.base.read(xb + 0x20, size)
            if size == 0x10000:
                data_uz = data_z
            else:
                data_uz = xpress.xpress_decode(data_z)
            for page, size, offset in self.PageDict[xb]:
                ofile.seek(page * 0x1000)
                ofile.write(data_uz[offset * 0x1000:offset * 0x1000 + 0x1000])
                page_count += 1
            del data_z, data_uz
            yield page_count

    def next_xpress(self, XpressHeader, XpressBlockSize):
        XpressHeaderOffset = XpressBlockSize + XpressHeader.obj_offset + \
                             XpressHeader.size()

        ## We only search this far
        BLOCKSIZE = 1024
        original_offset = XpressHeaderOffset
        while 1:
            data = self.base.read(XpressHeaderOffset, BLOCKSIZE)
            Magic_offset = data.find("\x81\x81xpress")
            if Magic_offset >= 0:
                XpressHeaderOffset += Magic_offset
                break
            else:
                XpressHeaderOffset += len(data)

            ## Only search this far in advance
            if XpressHeaderOffset - original_offset > 10240:
                return None, None

        XpressHeader = obj.Object("_IMAGE_XPRESS_HEADER", XpressHeaderOffset, self.base)
        XpressBlockSize = self.get_xpress_block_size(XpressHeader)

        return XpressHeader, XpressBlockSize

    def get_xpress_block_size(self, xpress_header):
        u0B = xpress_header.u0B.v() << 24
        u0A = xpress_header.u0A.v() << 16
        u09 = xpress_header.u09.v() << 8

        Size = u0B + u0A + u09
        Size = Size >> 10
        Size = Size + 1

        if ((Size % 8) == 0):
            return Size
        return (Size & ~7) + 8

    def get_header(self):
        return self.header

    def get_base(self):
        return self.base

    def get_signature(self):
        return self.header.Signature

    def get_system_time(self):
        return self.header.SystemTime

    def is_paging(self):
        return (self.ProcState.SpecialRegisters.Cr0.v() >> 31) & 1

    def is_pse(self):
        return (self.ProcState.SpecialRegisters.Cr4.v() >> 4) & 1

    def is_pae(self):
        return (self.ProcState.SpecialRegisters.Cr4.v() >> 5) & 1

    def get_number_of_memranges(self):
        return self.MemRangeCnt

    def get_number_of_pages(self):
        return self.PageIndex

    def get_addr(self, addr):
        page = addr >> page_shift
        if page in self.LookupCache:
            (hoffset, size, pageoffset) = self.LookupCache[page]
            return hoffset, size, pageoffset
        return None, None, None

    def get_block_offset(self, _xb, addr):
        page = addr >> page_shift
        if page in self.LookupCache:
            (_hoffset, _size, pageoffset) = self.LookupCache[page]
            return pageoffset
        return None

    def is_valid_address(self, addr):
        XpressHeaderOffset, _XpressBlockSize, _XpressPage = self.get_addr(addr)
        return XpressHeaderOffset != None

    def read_xpress(self, baddr, BlockSize):
        try:
            return self.PageCache.get(baddr)
        except KeyError:
            data_read = self.base.read(baddr, BlockSize)
            if BlockSize == 0x10000:
                data_uz = data_read
            else:
                data_uz = xpress.xpress_decode(data_read)

                self.PageCache.put(baddr, data_uz)

            return data_uz

    def fread(self, length):
        data = self.read(self.offset, length)
        self.offset += len(data)
        return data

    def _partial_read(self, addr, len):
        """ A function which reads as much as possible from the current page.

        May return a short read.
        """
        ## The offset within the page where we start
        page_offset = (addr & 0x00000FFF)

        ## How much data can we satisfy?
        available = min(PAGE_SIZE - page_offset, len)

        ImageXpressHeader, BlockSize, XpressPage = self.get_addr(addr)
        if not ImageXpressHeader:
            return None

        baddr = ImageXpressHeader + 0x20

        data = self.read_xpress(baddr, BlockSize)

        ## Each block decompressed contains 2**page_shift pages. We
        ## need to know which page to use here.
        offset = XpressPage * 0x1000 + page_offset

        return data[offset:offset + available]

    def read(self, addr, length):
        result = ''
        while length > 0:
            data = self._partial_read(addr, length)
            if not data:
                break

            addr += len(data)
            length -= len(data)
            result += data

        return result

    def zread(self, addr, length):
        raise NotImplementedError("Hibernation zread is not yet implemented")
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((length + (addr % 0x1000)) / 0x1000) - 1
        left_over = (length + addr) % 0x1000

        self.check_address_range(addr)

        ImageXpressHeader = self.get_addr(addr)
        if ImageXpressHeader == None:
            if length < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block)
        else:
            if length < first_block:
                return self.read(addr, length)
            stuff_read = self.read(addr, first_block)

        new_addr = addr + first_block

        for _i in range(0, full_blocks):
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
        _baseaddr = self.get_addr(addr)
        string = self.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_available_pages(self):
        page_list = []
        for _i, xb in enumerate(self.PageDict.keys()):
            for page, _size, _offset in self.PageDict[xb]:
                page_list.append([page * 0x1000, 0x1000])
        return page_list

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
        size = self.HighestPage * 0x1000 + 0x1000
        return [0, size]

    def check_address_range(self, addr):
        memrange = self.get_address_range()
        if addr < memrange[0] or addr > memrange[1]:
            raise IOError

    def get_available_addresses(self):
        """ This returns the ranges  of valid addresses """
        for i in self.AddressList:
            yield i

    def close(self):
        self.base.close()

    def write(self, _addr, _buf):
        if not self._config.WRITE:
            return False
        raise NotImplementedError("Writing to hibernation files has not been implemented yet")

#    def get_version(self):
#
#        if self.is_pae() == 1:
#            addr_space = standard.IA32PagedMemoryPae(self, self.ProcState.SpecialRegisters.Cr3.v())
#        else:
#            addr_space = standard.IA32PagedMemory(self, self.ProcState.SpecialRegisters.Cr3.v())
#
#        if addr_space == None:
#            return (None, None, None)
#
#        GdtIndex = (0x3B >> 3)
#        GdtrBase = read_obj(self.base, types,
#	     ['_KPROCESSOR_STATE', 'SpecialRegisters','Gdtr','Base'], \
#             self.ProcStateOffset)
#
#        NtTibAddr = GdtrBase + GdtIndex * obj_size(hiber_types,'_KGDTENTRY')
#
#        BaseLow = read_obj(addr_space, hiber_types,
#	     ['_KGDTENTRY','BaseLow'], NtTibAddr)
#
#        BaseMid = read_obj(addr_space, hiber_types,
#	     ['_KGDTENTRY','BaseMid'], NtTibAddr)
#
#        BaseHigh = read_obj(addr_space, hiber_types,
#	     ['_KGDTENTRY','BaseHigh'], NtTibAddr)
#
#        NtTibAddress = (BaseLow) | (BaseMid << (2 * 8)) | (BaseHigh << (3 * 8))
#
#        if ((NtTibAddress == 0) or (NtTibAddress > 0x80000000)):
#            return (None, None, None)
#
#        ProcessEnvironmentBlock =  read_obj(addr_space, types,
#	     ['_TEB', 'ProcessEnvironmentBlock'], NtTibAddress)
#
#        OSMajorVersion = read_obj(addr_space, types,
#	     ['_PEB', 'OSMajorVersion'], ProcessEnvironmentBlock)
#
#        OSMinorVersion = read_obj(addr_space, types,
#	     ['_PEB','OSMinorVersion'], ProcessEnvironmentBlock)
#
#        OSBuildNumber = read_obj(addr_space, types,
#	     ['_PEB','OSBuildNumber'],ProcessEnvironmentBlock)
#
#        return (OSMajorVersion, OSMinorVersion, OSBuildNumber)
