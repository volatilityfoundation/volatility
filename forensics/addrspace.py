# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Copyright (C) 2004,2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

""" Alias for all address spaces """

import os
import struct

class FileAddressSpace:
    def __init__(self, fname, mode='rb', fast=False):
        self.fname = fname
        self.name = fname
        self.fhandle = open(fname, mode)
        self.fsize = os.path.getsize(fname)

        if fast == True:
            self.fast_fhandle = open(fname, mode)

    def fread(self,len):
        return self.fast_fhandle.read(len)

    def read(self, addr, len):
        self.fhandle.seek(addr)        
        return self.fhandle.read(len)    

    def zread(self, addr, len):
        return self.read(addr, len)

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def get_address_range(self):
        return [0,self.fsize-1]

    def get_available_addresses(self):
        return [0,self.get_address_range()]

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return addr < self.fsize - 1

    def close():
        self.fhandle.close()
