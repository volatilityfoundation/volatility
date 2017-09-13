# Volatility
# AFF4 Standard v1 memory image reader
# Based on WindowsCrashDumpSpace32
#
# Copyright (C) 2017 Schatz Forensic
#
# Authors:
# bradley@schatzforensic.com (Bradley Schatz)
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
import volatility.plugins.addrspaces.standard as standard
import logging
import pyaff4
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4.container import Container

LOGGER = logging.getLogger("pyaff4")
LOGGER.setLevel(logging.ERROR)

# pylint: disable-msg=C0111

zipFileHeaderMAGIC = "\x50\x4b\x03\x04"


class AFF4AddressSpace(standard.FileAddressSpace):
    """ This AS supports AFF4 Containers """
    order = 31

    def __init__(self, base, config, **kwargs):
        standard.FileAddressSpace.__init__(self, base, config, layered=True)

        # Must be stacked on a Raw file based image
        self.as_assert(base, "No base address space provided")

        # Must start with the a Zip File Header
        self.as_assert((base.read(0, 4) == zipFileHeaderMAGIC), "Header signature invalid")

        # Cant stack an AFF4 image on another AFF4 images
        self.as_assert(type(base) != AFF4AddressSpace, "Cant stack AFF4 addressspace on same")
        self.fhandle = Container.open(self.name)
        self.fsize = self.fhandle.Size()
        self.fhandle.seek(0)
        dtb = self.fhandle.parent.getDTB()
        if dtb != 0:
            self.dtb = dtb

    def write(self, _addr, _buf):
        if not self._config.WRITE:
            return False
        raise NotImplementedError("Write support is not implemented for AFF4 containers")

    def get_header(self):
        return self.header

    def fread(self, length):
        length = int(length)
        return self.fhandle.read(length)

    def read(self, addr, length):
        addr, length = int(addr), int(length)
        try:
            self.fhandle.seek(addr)
        except (IOError, OverflowError):
            return None
        data = self.fhandle.read(length)
        if len(data) == 0:
            return None
        return data

    def zread(self, addr, length):
        data = self.read(addr, length)
        if data is None:
            data = "\x00" * length
        elif len(data) != length:
            data += "\x00" * (length - len(data))

        return data

    def read_long(self, addr):
        string = self.read(addr, 4)
        longval, = self._long_struct.unpack(string)
        return longval

    def get_available_addresses(self):
        """ This returns the ranges  of valid addresses """
        lastOffset = -1
        lastLength = -1
        for run in self.fhandle.GetRanges():
            offset = run.map_offset
            length = run.length
            if lastOffset == -1:
                lastOffset = offset
                lastLength = length
            else:
                if lastOffset + lastLength == offset:
                    # merge the two
                    lastLength = lastLength + length
                    continue
                else:
                    # emit the last
                    res = (lastOffset, lastLength)
                    lastOffset = offset
                    lastLength = length
                    yield res
        yield (lastOffset, lastLength)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return self.fhandle.tree.overlaps(addr)

    def close(self):
        self.fhandle.close()