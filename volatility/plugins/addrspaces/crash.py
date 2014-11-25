# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2005,2006,2007 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

""" An AS for processing crash dumps """
import struct
import volatility.obj as obj
import volatility.addrspace as addrspace

#pylint: disable-msg=C0111

page_shift = 12

class WindowsCrashDumpSpace32(addrspace.AbstractRunBasedMemory):
    """ This AS supports windows Crash Dump format """
    order = 30
    dumpsig = 'PAGEDUMP'
    headertype = "_DMP_HEADER"
    headerpages = 1
    _long_struct = struct.Struct("=I")

    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")

        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)

        ## Must start with the magic PAGEDUMP
        self.as_assert((base.read(0, 8) == self.dumpsig), "Header signature invalid")

        self.as_assert(self.profile.has_type(self.headertype), self.headertype + " not available in profile")
        self.header = obj.Object(self.headertype, 0, base)

        self.as_assert((self.header.DumpType == 0x1), "Unsupported dump format")

        offset = self.headerpages
        for x in self.header.PhysicalMemoryBlockBuffer.Run:
            self.runs.append((x.BasePage.v() * 0x1000,
                              offset * 0x1000,
                              x.PageCount.v() * 0x1000))
            offset += x.PageCount.v()

        self.dtb = self.header.DirectoryTableBase.v()

    def get_header(self):
        return self.header

    def get_base(self):
        return self.base

    def read_long(self, addr):
        _baseaddr = self.translate(addr)
        string = self.read(addr, 4)
        if not string:
            return obj.NoneObject("Could not read data at " + str(addr))
        longval, = self._long_struct.unpack(string)
        return longval

    def get_available_addresses(self):
        """ This returns the ranges  of valid addresses """
        for run in self.runs:
            yield (run[0], run[2])

    def close(self):
        self.base.close()

class WindowsCrashDumpSpace64(WindowsCrashDumpSpace32):
    """ This AS supports windows Crash Dump format """
    order = 30
    dumpsig = 'PAGEDU64'
    headertype = "_DMP_HEADER64"
    headerpages = 2
