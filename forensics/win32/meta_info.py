# Volatility
# Copyright (C) 2007,2008 Volatile Systems
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
@organization: Volatile Systems LLC
"""

# Global Variables
DirectoryTableBase = ""
KernelAddressSpace = ""

def set_dtb(dtb):
    global DirectoryTableBase 
    DirectoryTableBase = dtb

def set_kas(kas):
    global KernelAddressSpace
    KernelAddressSpace = kas

def set_datatypes(datatypes):
    global DataTypes
    DataTypes = datatypes
