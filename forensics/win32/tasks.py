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
@organization: Volatile Systems
"""

from forensics.object import *
from forensics.win32.datetime import *
#from forensics.win32.info import *
from forensics.win32.info import find_psactiveprocesshead
import os
from struct import unpack

from forensics.addrspace import *

def process_list(addr_space, types, symbol_table=None):
    """
    Get the virtual addresses of all Windows processes
    """
    plist = []
    
    PsActiveProcessHead = find_psactiveprocesshead(addr_space,types)

    if not PsActiveProcessHead is None:
        (offset, tmp)  = get_obj_offset(types, ['_EPROCESS', 'ActiveProcessLinks'])

        first_process = PsActiveProcessHead - offset

        current = read_obj(addr_space, types, ['_EPROCESS', 'ActiveProcessLinks', 'Flink'],
                           first_process)
        if current is None:
            print "Unable to read beginning of process list 0x%x. Try a different DTB?" % (first_process)
            return plist
        
        this_process = current - offset
        
        while current != PsActiveProcessHead:
            Type =  read_obj(addr_space, types, ['_EPROCESS', 'Pcb', 'Header','Type'], this_process)

            if not Type == 0x03:
                break
            plist.append(this_process)

            current = read_obj(addr_space, types, ['_EPROCESS', 'ActiveProcessLinks', 'Flink'],
                               this_process)
            if current == None:
                plist.append(this_process)
                break

            this_process = current - offset

    return plist


def process_find_pid(addr_space, types, symbol_table, all_tasks, pid):
    """
    Find process offset with this pid in the task list
    """
    match_tasks = []

    for task in all_tasks:
        process_id = process_pid(addr_space, types, task)
        if process_id == pid:
            match_tasks.append(task)

    return match_tasks
    
# Blocksize was chosen to make it aligned
# on 8 bytes
# Optimized by Michael Cohen

BLOCKSIZE = 1024 * 1024 * 10

def find_dtb(addr_space, types):
    """
    Find the Idle dtb (DTB Feeling lucky)
    """
   
    try:
        flat_address_space = FileAddressSpace(addr_space.name,fast=True)
    except:
        print "Unable to open image file %s" %filename
        return None

    offset = 0
    while 1:
        data = flat_address_space.fread(BLOCKSIZE)
        found = 0
        if not data:
            break

        while 1:
            found = data.find("\x03\x00\x1b\x00", found+1)
            if found >= 0:
                (type,size) = unpack('=HH',data[found:found+4])
                if process_imagename(addr_space,types,offset+found).find('Idle') != -1:
                    return process_dtb(addr_space, types, offset+found)

            else:
                break
            
        offset+=len(data)

    return None


def process_imagename(addr_space, types, task_vaddr):
    return read_null_string(addr_space, types,
                            ['_EPROCESS', 'ImageFileName'], task_vaddr)

def process_dtb(addr_space, types, task_vaddr):
    return read_obj(addr_space, types,
                    ['_EPROCESS', 'Pcb', 'DirectoryTableBase', 0], task_vaddr)

def process_vadroot(addr_space, types, task_vaddr):
    return read_obj(addr_space, types,
                        ['_EPROCESS', 'VadRoot'], task_vaddr)

def process_pid(addr_space, types, task_vaddr):
    return read_obj(addr_space, types,
                    ['_EPROCESS', 'UniqueProcessId'], task_vaddr)

def process_num_active_threads(addr_space, types, task_vaddr):
    return  read_obj(addr_space, types,
                     ['_EPROCESS', 'ActiveThreads'], task_vaddr)

def process_exit_status(addr_space, types, task_vaddr):
    return  read_obj(addr_space, types,
                         ['_EPROCESS', 'ExitStatus'], task_vaddr)

def process_inherited_from(addr_space, types, task_vaddr):
    return read_obj(addr_space, types,
                    ['_EPROCESS', 'InheritedFromUniqueProcessId'], task_vaddr)

def process_handle_table(addr_space, types, task_vaddr):
    return read_obj(addr_space, types,
                    ['_EPROCESS', 'ObjectTable'], task_vaddr)

def process_handle_count(addr_space, types, task_vaddr):
    object_table =  read_obj(addr_space, types,
                             ['_EPROCESS', 'ObjectTable'], task_vaddr)

    if object_table is None or not addr_space.is_valid_address(object_table):
        return None
    else:
        handle_count = read_obj(addr_space, types,
                                ['_HANDLE_TABLE', 'HandleCount'], object_table)

    return handle_count


def process_create_time(addr_space, types, task_vaddr):
    (create_time_offset, tmp) = get_obj_offset(types, ['_EPROCESS', 'CreateTime'])    
    create_time     = read_time(addr_space, types, task_vaddr + create_time_offset)

    if create_time is None:
        return None
    
    create_time     = windows_to_unix_time(create_time)
    return create_time

def process_exit_time(addr_space, types, task_vaddr):
    (exit_time_offset, tmp) = get_obj_offset(types, ['_EPROCESS', 'ExitTime'])    
    exit_time     = read_time(addr_space, types, task_vaddr + exit_time_offset)
    if exit_time is None:
        return None
    exit_time     = windows_to_unix_time(exit_time)
    return exit_time

def process_addr_space(kaddr_space, types, task_vaddr, fname=None):
    directory_table_base =  read_obj(kaddr_space, types,
                                     ['_EPROCESS', 'Pcb', 'DirectoryTableBase', 0], task_vaddr)

    try:
        #process_address_space = type(kaddr_space)(fname, directory_table_base)
        process_address_space = kaddr_space.__class__(kaddr_space.base, directory_table_base)
    except:
        return None

    return process_address_space


def process_peb(addr_space, types, task_vaddr):
    return read_obj(addr_space, types,
                    ['_EPROCESS', 'Peb'], task_vaddr)

def process_threadlisthead(addr_space, types, task_vaddr):
    return read_obj(addr_space, types,
                    ['_EPROCESS', 'ThreadListHead', 'Flink'], task_vaddr)

def create_addr_space(kaddr_space, directory_table_base):

    try:
        process_address_space = kaddr_space.__class__(kaddr_space.base, directory_table_base)
    except:
        return None

    return process_address_space

def process_command_line(process_address_space, types, peb_vaddr):
    process_parameters = read_obj(process_address_space, types,
                                  ['_PEB', 'ProcessParameters'], peb_vaddr)
    
    
    if process_parameters is None:
        return None
    
    return read_unicode_string(process_address_space, types,
                               ['_RTL_USER_PROCESS_PARAMETERS', 'CommandLine'],
                               process_parameters)    

def peb_number_processors(process_address_space, types, peb_vaddr):
    return read_obj(process_address_space, types,
                                  ['_PEB', 'NumberOfProcessors'], peb_vaddr)

def peb_csdversion(process_address_space, types, peb_vaddr):
    return read_unicode_string(process_address_space, types,
                                  ['_PEB', 'CSDVersion'], peb_vaddr)

def module_path(process_address_space, types, module_vaddr):
    return read_unicode_string(process_address_space, types,
                    ['_LDR_DATA_TABLE_ENTRY', 'FullDllName'], module_vaddr)    
def module_size(process_address_space, types, module_vaddr):
    return read_obj(process_address_space, types,
                    ['_LDR_DATA_TABLE_ENTRY', 'SizeOfImage'], module_vaddr)

def module_base(process_address_space, types, module_vaddr):
    return read_obj(process_address_space, types,
                    ['_LDR_DATA_TABLE_ENTRY', 'DllBase'], module_vaddr)

def process_ldrs(process_address_space, types, peb_vaddr):
    ldr = read_obj(process_address_space, types,
                   ['_PEB', 'Ldr'], peb_vaddr)

    module_list = []

    if ldr is None:
        print "Unable to read ldr for peb 0x%x" % (peb_vaddr)
        return module_list

    first_module = read_obj(process_address_space, types,
                            ['_PEB_LDR_DATA', 'InLoadOrderModuleList', 'Flink'],
                            ldr)

    if first_module is None:
        print "Unable to read first module for ldr 0x%x" % (ldr)
        return module_list        
    
    this_module = first_module

    next_module = read_obj(process_address_space, types,
                         ['_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks', 'Flink'],
                           this_module)

    if next_module is None:
        print "ModuleList Truncated, unable to read module at 0x%x\n" % (this_module)        
        return module_list
    
    while next_module != first_module:
        module_list.append(this_module)
        if not process_address_space.is_valid_address(next_module):
            print "ModuleList Truncated, unable to read module at 0x%x\n" % (next_module)
            return module_list
        prev_module = this_module
        this_module = next_module
        next_module = read_obj(process_address_space, types,
                         ['_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks', 'Flink'],
                         this_module)

        
    return module_list


def find_csdversion(addr_space, types):

    CSDVersionDict = dict()
    all_tasks = process_list(addr_space, types)

    for task in all_tasks:

        if not addr_space.is_valid_address(task):
            continue
        
        process_address_space = process_addr_space(addr_space, types, task)
        if process_address_space is None:
            continue
                            
        peb = process_peb(addr_space, types, task)

        try:
            if not process_address_space.is_valid_address(peb):
                continue
        except:
            continue

        CSDVersion = peb_csdversion(process_address_space, types, peb)
        if CSDVersion in CSDVersionDict:
            CSDVersionDict[CSDVersion] +=1
        else:
            CSDVersionDict[CSDVersion] = 1

    MaxCSDVersion = max([ (CSDVersionDict[x],x) for x in CSDVersionDict])[1]

    return MaxCSDVersion
