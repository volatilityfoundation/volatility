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

from forensics.symbols import *

nopae_syms = SymbolTable({
    'HandleTableListHead' : 0x805617c8,\
    'PsIdleProcess' : 0x805604d4,\
    'PsActiveProcessHead' : 0x805604d8 ,\
    'PsLoadedModuleList' : 0x8055a420,\
    })

pae_syms = SymbolTable({
    'HandleTableListHead' : 0x8055a548,\
    'PsIdleProcess' : 0x80559254,\
    'PsActiveProcessHead' : 0x80559258,\
    'PsLoadedModuleList' : 0x805531a0,\
    })
