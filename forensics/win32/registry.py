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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems LLC
"""

from forensics.object import *
from forensics.win32.info import *
from forensics.win32.datetime import windows_to_unix_time
from forensics.addrspace import FileAddressSpace
from forensics.win32.handles import handle_entry_object,is_object_key,object_data

def print_entry_keys(addr_space, types, entry):

    if not addr_space.is_valid_address(entry):
    	return

    obj = handle_entry_object(addr_space, types, entry)

    if obj is None:
        return
    
    if addr_space.is_valid_address(obj):
        if is_object_key(addr_space, types, obj):
	    
            key = object_data(addr_space, types, obj)

            KeyControlBlock = read_obj(addr_space, types,
	                        ['_CM_KEY_BODY', 'KeyControlBlock'], key)

            if not addr_space.is_valid_address(KeyControlBlock):
                return

            NameBlock = read_obj(addr_space, types,
	               ['_CM_KEY_CONTROL_BLOCK', 'NameBlock'], KeyControlBlock)

            if addr_space.is_valid_address(NameBlock):
                NameLength = read_obj(addr_space, types,
                      ['_CM_NAME_CONTROL_BLOCK', 'NameLength'], NameBlock)

                OutName = read_string(addr_space, types, ['_CM_NAME_CONTROL_BLOCK', 'Name'] , NameBlock , NameLength)
                if not OutName: OutName = "????????"
            else:
                OutName = "????????"

            ParentKcb = read_obj(addr_space, types,
                ['_CM_KEY_CONTROL_BLOCK', 'ParentKcb'], KeyControlBlock)

            while ( ParentKcb != 0 and addr_space.is_valid_address(ParentKcb)):
                NameBlock = read_obj(addr_space, types,
                    ['_CM_KEY_CONTROL_BLOCK', 'NameBlock'], ParentKcb)
                if addr_space.is_valid_address(NameBlock):
                    NameLength = read_obj(addr_space, types,
                        ['_CM_NAME_CONTROL_BLOCK', 'NameLength'], NameBlock)
                    Name = read_string(addr_space, types, ['_CM_NAME_CONTROL_BLOCK', 'Name'] , NameBlock , NameLength)
                    if not Name: Name = "????????"
                    OutName = Name + '\\' + OutName
                else:
                    OutName = "????????" + '\\' + OutName
                ParentKcb = read_obj(addr_space, types,
                        ['_CM_KEY_CONTROL_BLOCK', 'ParentKcb'], ParentKcb)
            OutName = '\\' + OutName
            return OutName
