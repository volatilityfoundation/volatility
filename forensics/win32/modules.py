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

from forensics.object import *
from forensics.win32.info import *

def modules_list(addr_space, types, symbol_table):
    """
    Get the virtual addresses of all Windows modules 
    """
    modules_list = []

    PsLoadedModuleList = find_psloadedmodulelist(addr_space, types)

    if not PsLoadedModuleList is None:
        (offset, tmp)  = get_obj_offset(types, \
	     ['_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks'])

        first_module = PsLoadedModuleList - offset

        current = read_obj(addr_space, types, \
	     ['_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks', 'Flink'],
                           first_module)
        
        this_module = current - offset
        
        next =  read_obj(addr_space, types, \
	     ['_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks', 'Flink'],
                         this_module)        

        while this_module != PsLoadedModuleList:

            if not addr_space.is_valid_address(this_module):
                print "Module list truncated, unable to read 0x%x." % (this_module)
                return modules_list

            modules_list.append(this_module)
            current = read_obj(addr_space, types, \
	        ['_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks', 'Flink'],
                               this_module)
            this_module = current - offset

            if not addr_space.is_valid_address(this_module):
                print "ModuleList Truncated Invalid Module"
                return modules_list

    return modules_list

def module_imagename(address_space, types, module_vaddr):
    return read_unicode_string(address_space, types,
        ['_LDR_DATA_TABLE_ENTRY', 'FullDllName'], module_vaddr)

def module_modulename(address_space, types, module_vaddr):
    return read_unicode_string(address_space, types,
        ['_LDR_DATA_TABLE_ENTRY', 'BaseDllName'], module_vaddr)

def module_imagesize(address_space, types, module_vaddr):
    return read_obj(address_space, types,
        ['_LDR_DATA_TABLE_ENTRY', 'SizeOfImage'], module_vaddr)

def module_baseaddr(address_space, types, module_vaddr):
    return read_obj(address_space, types,
        ['_LDR_DATA_TABLE_ENTRY', 'DllBase'], module_vaddr)

def module_find_baseaddr(addr_space, types,modules,name):
    for module in modules:
        module_name = module_imagename(addr_space, types, module)
        if module_name is None:
            continue

        if module_name.find(name) != -1:
            return module_baseaddr(addr_space, types, module)
