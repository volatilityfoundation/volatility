# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
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
@author:       AAron Walters 
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems LLC
"""

from forensics.object import *
from forensics.win32.datetime import *
from forensics.win32.tasks import *

LEVEL_MASK = 0x00000003
TABLE_MASK = 0xfffffff8
ADDR_SIZE  = 4


def handle_process_id(addr_space, types, table_vaddr):
    return read_obj(addr_space, types,
                    ['_HANDLE_TABLE', 'UniqueProcessId'], table_vaddr)


def handle_num_entries(addr_space, types, table_vaddr):
    return read_obj(addr_space, types,
                    ['_HANDLE_TABLE', 'HandleCount'], table_vaddr)

def handle_table_code(addr_space, types, table_vaddr):
    return read_obj(addr_space, types,
                    ['_HANDLE_TABLE', 'TableCode'], table_vaddr) & TABLE_MASK


def handle_table_levels(addr_space, types, table_vaddr):
    return read_obj(addr_space, types,
                    ['_HANDLE_TABLE', 'TableCode'], table_vaddr) & LEVEL_MASK

def handle_table_L1_addr(addr_space, types, table_vaddr, entry_num):
    return handle_table_code(addr_space, types, table_vaddr) + \
           ADDR_SIZE * entry_num

def handle_table_L2_addr(addr_space, types, L1_table, L2):
    if L1_table != 0x0:
        L2_entry = L1_table + ADDR_SIZE * L2
        return L2_entry
    return None

def handle_table_L1_entry(addr_space, types, table_vaddr, entry_num):
    return handle_table_code(addr_space, types, table_vaddr) + \
           obj_size(types, '_HANDLE_TABLE_ENTRY') * entry_num

def handle_table_L2_entry(addr_space, types, table_vaddr, L1_table, L2):
    if L1_table != 0x0:
        L2_entry = L1_table + obj_size(types, '_HANDLE_TABLE_ENTRY') * L2
        
        return L2_entry
    
    return None

def handle_table_L3_entry(addr_space, types, table_vaddr, L2_table, L3):
    if L2_table != 0x0:
        L3_entry = L2_table + obj_size(types, '_HANDLE_TABLE_ENTRY') * L3
        
        return L3_entry

    return None
                    
def handle_entry_object(addr_space, types, entry_vaddr):
    handle_object = read_obj(addr_space, types,
                        ['_HANDLE_TABLE_ENTRY', 'Object'], entry_vaddr)
    if handle_object is None:
        return None
 
    return handle_object & ~0x00000007

def addr_entry(addr_space, types, entry_vaddr):
    entry = read_value(addr_space, 'unsigned long', entry_vaddr)
    if entry is None:
        return None

    return entry


def is_object_key(addr_space, types, obj_vaddr):

    type_vaddr = read_obj(addr_space, types,
                          ['_OBJECT_HEADER', 'Type'], obj_vaddr)

    if not addr_space.is_valid_address(type_vaddr):
        return False

    type_name = read_unicode_string(addr_space, types,
                                    ['_OBJECT_TYPE', 'Name'], type_vaddr)

    return not type_name is None and type_name == "Key"

def is_object_file(addr_space, types, obj_vaddr):
    type_vaddr = read_obj(addr_space, types,
                          ['_OBJECT_HEADER', 'Type'], obj_vaddr)

    if not addr_space.is_valid_address(type_vaddr):
        return False

    type_name = read_unicode_string(addr_space, types,
                                    ['_OBJECT_TYPE', 'Name'], type_vaddr)

    return not type_name is None and type_name.find("File") != -1

def object_data(addr_space, types, obj_vaddr):
    (offset, tmp) = get_obj_offset(types, ['_OBJECT_HEADER', 'Body'])
    return obj_vaddr + offset

def file_name(addr_space, types, file_vaddr):
    return read_unicode_string(addr_space, types,
                               ['_FILE_OBJECT', 'FileName'],
                               file_vaddr)

def handle_tables(addr_space, types, symtab, pid=None):

    htables = []

    all_tasks = process_list(addr_space, types, symtab)

    for task in all_tasks:
        if not addr_space.is_valid_address(task):
            continue
        ObjectTable = process_handle_table(addr_space, types, task)
        process_id = process_pid(addr_space, types, task)

        if addr_space.is_valid_address(ObjectTable):
            if pid == None: 
                htables.append(ObjectTable)
            else:
                if process_id == pid:
                    htables.append(ObjectTable)
    
    return htables


def handle_entries(addr_space, types, table):
        # In the case of Windows 2000, the table sizes are limited
        # to at most 256 entries since they are only addressed with 8 bits.

        all_entries = []

        table_code = handle_table_code(addr_space, types, table)

        if table_code == 0:
            return all_entries

        table_levels = handle_table_levels(addr_space, types, table)

        if table_levels == 0:
            num_entries = handle_num_entries(addr_space, types, table)

            for counter in range(0, 0x200):
                entry = handle_table_L1_entry(addr_space, types, table, counter)
                if entry != None and entry !=0:
                    all_entries.append(entry)
                        
        elif table_levels == 1:
            for i in range(0, 0x400):
                L1_entry = handle_table_L1_addr(addr_space, types, table, i)
                if not L1_entry is None:
                    L1_table = addr_entry(addr_space, types, L1_entry)
                    if L1_table is None:
                        continue

                    for j in range(0, 0x200):
                        L2_entry = handle_table_L2_entry(addr_space, types, table, L1_table, j)
                        if not L2_entry is None:
                            all_entries.append(L2_entry)

        elif table_levels == 2:
            for i in range(0, 0x400):
                L1_entry = handle_table_L1_addr(addr_space, types, table, i)
                if not L1_entry is None:
                    L1_table = addr_entry(addr_space, types, L1_entry)
                    if L1_table is None:
                        continue
                    for j in range(0, 0x400):
                        L2_entry = handle_table_L2_addr(addr_space, types, L1_table, j)
                        if not L2_entry is None:
                            L2_table = addr_entry(addr_space, types, L2_entry)
                            if L2_table is None:
                                continue
                            for k in range(0, 0x200):
                                L3_entry = handle_table_L3_entry(addr_space, types, table, L2_table, k)
                                if not L3_entry is None: 
                                    all_entries.append(L3_entry)       
        return all_entries
