# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
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

import struct
from forensics.addrspace import BufferAddressSpace

builtin_types = { \
    'int' : (4, 'l'), \
    'long': (4, 'l'), \
    'unsigned long' : (4, 'L'), \
    'unsigned int' : (4, 'I'), \
    'address' : (4, 'L'), \
    'char' : (1, 'c'), \
    'unsigned char' : (1, 'B'), \
    'unsigned short' : (2, 'H'), \
    'short' : (2, 'h'), \
    'long long' : (8, 'q'), \
    'unsigned long long' : (8, 'Q'), \
    'pointer' : (4, 'L'),\
    }


def obj_size(types, objname):
    if not types.has_key(objname):
        raise Exception('Invalid type %s not in types' % (objname))

    return types[objname][0]

def builtin_size(builtin):
    if not builtin_types.has_key(builtin):
        raise Exception('Invalid built-in type %s' % (builtin))

    return builtin_types[builtin][0]

def read_value(addr_space, value_type, vaddr):
    """
    Read the low-level value for a built-in type. 
    """

    if not builtin_types.has_key(value_type):
        raise Exception('Invalid built-in type %s' % (value_type))

    type_unpack_char = builtin_types[value_type][1]
    type_size        = builtin_types[value_type][0]

    buf = addr_space.read(vaddr, type_size)
    if buf is None:
        return None

    (val, ) = struct.unpack('='+type_unpack_char, buf)

    return val


def read_unicode_string(addr_space, types, member_list, vaddr):
    offset = 0
    if len(member_list) > 1:
        (offset, current_type) = get_obj_offset(types, member_list)


    buf    = read_obj(addr_space, types, ['_UNICODE_STRING', 'Buffer'], vaddr + offset)
    length = read_obj(addr_space, types, ['_UNICODE_STRING', 'Length'], vaddr + offset)

    if length == 0x0:
        return ""

    if buf is None or length is None:
        return None

    readBuf = read_string(addr_space, types, ['char'], buf, length)

    if readBuf is None:
        return None
    
    try:
        readBuf = readBuf.decode('UTF-16').encode('ascii', 'backslashreplace')
    except:
        return None
    
    return readBuf

def read_unicode_string_buf(data, virt_addr_space, types, member_list, doffset):
    '''
    Reads a unicode string in virtual address space that is indicated
    by a pointer in a buffer (e.g. in pool scanners)
    '''       
    
    phys_addr_space = BufferAddressSpace(data)
    return read_unicode_string_p(phys_addr_space, virt_addr_space, types, member_list, doffset)

def read_unicode_string_p(phys_addr_space, virt_addr_space, types, member_list, phys_addr):
    '''
    Reads a unicode string in virtual address space that is indicated
    by a pointer into physical address space
    '''    

    offset = 0
    if len(member_list) > 1:
        (offset, current_type) = get_obj_offset(types, member_list)

    # read string length and buffer pointer into virtual address space
    buf    = read_obj(phys_addr_space, types, ['_UNICODE_STRING', 'Buffer'], phys_addr + offset)
    length = read_obj(phys_addr_space, types, ['_UNICODE_STRING', 'Length'], phys_addr + offset)
    
    if buf is None or length is None:
        return None

    readBuf = read_string(virt_addr_space, types, ['char'], buf, length)

    if readBuf is None:
        return None
    
    try:
        readBuf = readBuf.decode('UTF-16').encode('ascii','backslashreplace')
    except:
        return None
    
    return readBuf
    

def read_string(addr_space, types, member_list, vaddr, max_length=256):
    offset = 0
    if len(member_list) > 1:
        (offset, current_type) = get_obj_offset(types, member_list)

    val = addr_space.read(vaddr + offset, max_length)

    return val    
    
def read_string_buf(data, types, member_list, vaddr, max_length=256):
    addr_space = BufferAddressSpace(data)
    return read_string(addr_space, types, member_list, vaddr, max_length=256)

def read_null_string(addr_space, types, member_list, vaddr, max_length=256):
    string = read_string(addr_space, types, member_list, vaddr, max_length)

    if string is None:
        return None

    if (string.find('\0') == -1):
        return string
    (string, none) = string.split('\0', 1)
    return string
        
def get_obj_offset(types, in_member_list):
    """
    Returns the (offset, type) pair for a given list
    """
    member_list = in_member_list[:]
    member_list.reverse()

    current_type = member_list.pop()

    offset = 0

    while (len(member_list) > 0):
        if current_type == 'array':
            current_type = member_dict[current_member][1][2][0]
            if current_type in builtin_types:
                current_type_size = builtin_size(current_type)
            else:
                current_type_size = obj_size(types, current_type)
            index = member_list.pop()
            offset += index * current_type_size
            continue
            
        elif not types.has_key(current_type):
            raise Exception('Invalid type ' + current_type)
        
        member_dict = types[current_type][1]
        
        current_member = member_list.pop()
        if not member_dict.has_key(current_member):
            raise Exception('Invalid member %s in type %s' % (current_member, current_type))

        offset += member_dict[current_member][0]

        current_type = member_dict[current_member][1][0]

    return (offset, current_type)


def read_obj(addr_space, types, member_list, vaddr):
    """
    Read the low-level value for some complex type's member.
    The type must have members.
    """
    if len(member_list) < 2:
        raise Exception('Invalid type/member ' + str(member_list))
    

    
    (offset, current_type) = get_obj_offset(types, member_list)
    return read_value(addr_space, current_type, vaddr + offset)


def read_obj_from_buf(data,types,member_list,doffset):
    addr_space = BufferAddressSpace(data)
    return read_obj(addr_space, types, member_list, doffset)
