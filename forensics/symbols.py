# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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
@author:       AAron Walters and Nick Petroni
@license:      GNU General Public License 2.0 or later
@contact:      awalters@komoku.com, npetroni@komoku.com
@organization: Komoku, Inc.
"""

from forensics.object import read_value

class SymbolTable:
    def __init__(self, sym_dict):
        self.dict = sym_dict
        
    def lookup(self, sym):
        if self.dict.has_key(sym):
            return self.dict[sym]
        else:
            return None

    def sym_value(self, sym, addr_space):
        if self.dict.has_key(sym):
            return read_value(addr_space, 'unsigned long', self.lookup(sym))
        else:
            return None
