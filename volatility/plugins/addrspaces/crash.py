# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2005,2006,2007 4tphi Research
#
# Authors: 
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

""" An AS for processing crash dumps """
import struct
import volatility.obj as obj
import volatility.plugins.addrspaces.standard as standard

#pylint: disable-msg=C0111

page_shift = 12

class WindowsCrashDumpSpace32(standard.FileAddressSpace):
    """ This AS supports windows Crash Dump format """
    order = 30
    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")

        standard.FileAddressSpace.__init__(self, base, config, layered = True, **kwargs)

        ## Must start with the magic PAGEDUMP
        self.as_assert((base.read(0, 8) == 'PAGEDUMP'), "Header signature invalid")

        self.runs = []
        # I have the feeling config.OFFSET will interfere with plugin options...
        self.offset = 0 # config.OFFSET
        self.fname = ''

        self.as_assert(self.profile.has_type("_DMP_HEADER"), "_DMP_HEADER not available in profile")
        self.header = obj.Object("_DMP_HEADER", self.offset, base)

        self.runs = [ (x.BasePage.v(), x.PageCount.v())
                      for x in self.header.PhysicalMemoryBlockBuffer.Run ]

        self.dtb = self.header.DirectoryTableBase.v()

    def convert_to_raw(self, ofile):
        page_count = 0
        current_file_page = 0x1000
        for run in self.runs:
            page, count = run

            ofile.seek(page * 0x1000)
            for j in xrange(0, count * 0x1000, 0x1000):
                data = self.base.read(current_file_page + j, 0x1000)
                ofile.write(data)
                page_count += 1
                # If there's only one run, this leaves the user in the dark,
                # so instead we yield for every page
                yield page_count
            current_file_page += (count * 0x1000)

    def get_header(self):
        return self.header

    def get_base(self):
        return self.base

    def get_addr(self, addr):
        page_offset = (addr & 0x00000FFF)
        page = addr >> page_shift

        # This is the offset to account for the header file
        offset = 1
        for run in self.runs:
            if ((page >= run[0]) and (page < (run[0] + run[1]))):
                run_offset = page - run[0]
                offset = offset + run_offset
                baseoffset = (offset * 0x1000) + page_offset
                return baseoffset
            offset += run[1]
        return None

    def is_valid_address(self, addr):
        return self.get_addr(addr) != None

    def read(self, addr, length):
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

    def write(self, vaddr, buf):
        baddr = self.get_addr(vaddr)
        return standard.AbstractWritablePagedMemory.write(self, baddr, buf)

    def zread(self, vaddr, length):
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000

        self.check_address_range(vaddr)

        baddr = self.get_addr(vaddr)

        if baddr == None:
            if length < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block)
        else:
            if length < first_block:
                return self.base.read(baddr, length)
            stuff_read = self.base.read(baddr, first_block)

        new_vaddr = vaddr + first_block
        for _i in range(0, full_blocks):
            baddr = self.get_addr(new_vaddr)
            if baddr == None:
                stuff_read = stuff_read + ('\0' * 0x1000)
            else:
                stuff_read = stuff_read + self.base.read(baddr, 0x1000)

            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            baddr = self.get_addr(new_vaddr)
            if baddr == None:
                stuff_read = stuff_read + ('\0' * left_over)
            else:
                stuff_read = stuff_read + self.base.read(baddr, left_over)
        return stuff_read

    def read_long(self, addr):
        _baseaddr = self.get_addr(addr)
        string = self.read(addr, 4)
        if not string:
            return obj.NoneObject("Could not read data at " + str(addr))
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_available_pages(self):
        page_list = []
        for run in self.runs:
            start = run[0]
            for page in range(start, start + run[1]):
                page_list.append([page * 0x1000, 0x1000])
        return page_list

    def get_number_of_pages(self):
        return len(self.get_available_pages())

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
        run = self.runs[-1]
        size = run[0] * 0x1000 + run[1] * 0x1000
        return [0, size]

    def get_available_addresses(self):
        """ This returns the ranges  of valid addresses """
        for run in self.runs:
            yield (run[0] * 0x1000, run[1] * 0x1000)

    def get_runs(self):
        """This returns the crashdump runs"""
        return self.runs

    def check_address_range(self, addr):
        memrange = self.get_address_range()
        if addr < memrange[0] or addr > memrange[1]:
            raise IOError

    def close(self):
        self.base.close()
