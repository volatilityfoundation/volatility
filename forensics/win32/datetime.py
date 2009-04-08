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
from time import gmtime, strftime


def windows_to_unix_time(windows_time):
    """
    Converts Windows 64-bit time to UNIX time

    @type  windows_time:  Integer
    @param windows_time:  Windows time to convert (64-bit number)

    @rtype  Integer
    @return  UNIX time
    """
    if(windows_time == 0):
        unix_time =0
    else:
        unix_time = windows_time / 10000000
        unix_time = unix_time - 11644473600

    if unix_time < 0:
        unix_time = 0

    return unix_time


def read_time(addr_space, types, vaddr):
    low_time  = read_obj(addr_space, types,
                         ['_KSYSTEM_TIME', 'LowPart'], vaddr)
    high_time = read_obj(addr_space, types,
                         ['_KSYSTEM_TIME', 'High1Time'], vaddr)

    if low_time == None or high_time == None:
        return None

    return (high_time << 32) | low_time

def read_time_buff(buff, types, vaddr):
    low_time  = read_obj_from_buf(buff, types,
                         ['_KSYSTEM_TIME', 'LowPart'], vaddr)
    high_time = read_obj_from_buf(buff, types,
                         ['_KSYSTEM_TIME', 'High1Time'], vaddr)

    if low_time == None or high_time == None:
        return None

    return (high_time << 32) | low_time

def read_time_buf(buff,data_types,member_list,object_offset):
    (time_offset, tmp) = get_obj_offset(data_types, \
        member_list)

    low_time  = read_obj_from_buf(buff, data_types, \
        ['_KSYSTEM_TIME', 'LowPart'], object_offset+time_offset)
    high_time = read_obj_from_buf(buff, data_types, \
        ['_KSYSTEM_TIME', 'High1Time'], object_offset+time_offset )

    if low_time == None or high_time == None:
        return None

    read_time = (high_time << 32) | low_time
                     
    read_time = windows_to_unix_time(read_time)
    return read_time

def local_time(addr_space, types, vaddr):
    """
    Returns the 64-bit numerical local time (100ns units)
    
    @type  addr_space:  AddressSpace
    @param addr_space:  the kernel address space

    @type  types:       Dictionary
    @param types:       Type (struct) formats dictionary

    @type  vaddr:       Integer
    @param vaddr:       virtual address of KUSER_SHARED_DATA

    @rtype Integer
    @return   returns the 64-bit system time number
    """
    return system_time(addr_space, types, vaddr) - \
           time_zone_bias(addr_space, types, vaddr)

def system_time(addr_space, types, vaddr):
    """
    Returns the 64-bit numerical system time (100ns units)
    
    @type  addr_space:  AddressSpace
    @param addr_space:  the kernel address space

    @type  types:       Dictionary
    @param types:       Type (struct) formats dictionary

    @type  vaddr:       Integer
    @param vaddr:       virtual address of

    @rtype Integer
    @return   returns the 64-bit system time number
    """
    (offset, tmp) = get_obj_offset(types, ['_KUSER_SHARED_DATA', 'SystemTime'])
    
    return read_time(addr_space, types, vaddr + offset)

def time_zone_bias(addr_space, types, vaddr):
    """
    Returns the 64-bit numerical timezone bias (100ns units)
    
    @type  addr_space:  AddressSpace
    @param addr_space:  the kernel address space

    @type  types:       Dictionary
    @param types:       Type (struct) formats dictionary

    @type  vaddr:       Integer
    @param vaddr:       virtual address of KUSER_SHARED_DATA

    @rtype Integer
    @return   returns the 64-bit system time number
    """
    (offset, tmp) = get_obj_offset(types, ['_KUSER_SHARED_DATA', 'TimeZoneBias'])
    
    return read_time(addr_space, types, vaddr + offset)


