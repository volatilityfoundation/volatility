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
from forensics.win32.modules import *
from socket import ntohs, inet_ntoa

module_versions = { \
'MP' : { \
  'TCBTableOff' : [0x497e8], \
  'SizeOff' : [0x3f7c8], \
  'AddrObjTableOffset' : [0x48760], \
  'AddrObjTableSizeOffset' : [0x48764], \
},
'UP' : { \
  'TCBTableOff' : [0x495e8], \
  'SizeOff' : [0x3f5bc], \
  'AddrObjTableOffset' : [0x48560], \
  'AddrObjTableSizeOffset' : [0x48564], \
},
'2180' : { \
  'TCBTableOff' : [0x493e8], \
  'SizeOff' : [0x3f3b0], \
  'AddrObjTableOffset'  : [0x48360], \
  'AddrObjTableSizeOffset' : [0x48364], \
},
'3244' : { \
  'TCBTableOff' : [0x496E8], \
  'SizeOff' : [0x3F6BC], \
  'AddrObjTableOffset'  : [0x48660], \
  'AddrObjTableSizeOffset' : [0x48664], \
},
'3394': {
    'TCBTableOff': [0x49768], \
    'SizeOff': [0x3F73C], \
    'AddrObjTableOffset': [0x486E0], \
    'AddrObjTableSizeOffset': [0x486E4], \
},
'5625' : { \
  'TCBTableOff' : [0x49ae8], \
  'SizeOff' : [0x3fac8], \
  'AddrObjTableOffset'  : [0x48a60], \
  'AddrObjTableSizeOffset' : [0x48a64], \
},
'2111' : { \
  'TCBTableOff' : [0x49A68], \
  'SizeOff' : [0x3FA48], \
  'AddrObjTableOffset'  : [0x489E0], \
  'AddrObjTableSizeOffset' : [0x489E4], \
}
}


def tcb_connections(addr_space, types, symbol_table):
    all_modules = modules_list(addr_space, types, symbol_table)
    base_addr = module_find_baseaddr(addr_space, types, all_modules,"tcpip")

    if base_addr is None:
        return []

    connection_list = []

    connection_list = find_connections(addr_space, types, symbol_table, base_addr)

    return connection_list

def get_tcb_connections(addr_space, types, symbol_table, base_addr, TCBTableOff, SizeOff):

    TCBTable = base_addr + TCBTableOff 
    MaxHashTableSize = base_addr + SizeOff


    TCBTableAddr = read_value(addr_space, 'unsigned long', TCBTable)

    if TCBTableAddr == None:
        return []

    if not addr_space.is_valid_address(TCBTableAddr):
        return []

    TableSize = read_value(addr_space, 'unsigned long', MaxHashTableSize)

    if TableSize == None:
       return []

    connection_list = []
    for cnt in range(0,TableSize):
        EntryAddress=TCBTableAddr + 4*cnt

        if not addr_space.is_valid_address(EntryAddress):
            continue

        TableEntry = read_value(addr_space, 'unsigned long', EntryAddress)
        if TableEntry == 0 or TableEntry == None:
            continue

        next = read_obj(addr_space, types,
                        ['_TCPT_OBJECT', 'Next'], TableEntry)

        while next != 0x0:
            if not addr_space.is_valid_address(next):
                print "ConnectionList Truncated Invalid 0x%x"%next
                return connection_list
            connection_list.append(next)
            next = read_obj(addr_space, types,
                            ['_TCPT_OBJECT', 'Next'], next)

        connection_list.append(TableEntry)

    return connection_list


def find_connections(addr_space, types, symbol_table, base_addr):

    connection_list = []

    for offsets in module_versions:
        offsets = module_versions[offsets]
         
        connection_list = get_tcb_connections(addr_space, types, symbol_table, base_addr, offsets['TCBTableOff'][0], offsets['SizeOff'][0])
        if len(connection_list) > 0:
            return connection_list

    return connection_list


def connection_pid(addr_space, types, connection_vaddr):
    return read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'Pid'], connection_vaddr)

def connection_lport(addr_space, types, connection_vaddr):
    return ntohs(read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'LocalPort'], connection_vaddr))

def connection_laddr(addr_space, types, connection_vaddr):
    laddr = read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'LocalIpAddress'], connection_vaddr)
    return inet_ntoa(struct.pack('=L',laddr)) 

def connection_rport(addr_space, types, connection_vaddr):
    return ntohs(read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'RemotePort'], connection_vaddr))

def connection_raddr(addr_space, types, connection_vaddr):
    raddr = read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'RemoteIpAddress'], connection_vaddr)
    return inet_ntoa(struct.pack('=L',raddr))    

def open_sockets(addr_space, types, symbol_table):
    all_modules = modules_list(addr_space, types, symbol_table)
    base_addr = module_find_baseaddr(addr_space, types, all_modules,"tcpip")

    if base_addr is None:
        return []

    socket_list = []

    socket_list = find_sockets(addr_space, types, symbol_table, base_addr)

    return socket_list

def get_open_sockets(addr_space, types, symbol_table, base_addr, AddrObjTableOffset, AddrObjTableSizeOffset):
    
    AddrObjTable = base_addr + AddrObjTableOffset 
    AddrObjTableSize = base_addr + AddrObjTableSizeOffset

    AddrObjAddr   = read_value(addr_space, 'unsigned long', AddrObjTable)
    AddrTableSize = read_value(addr_space, 'unsigned long', AddrObjTableSize)

    if AddrObjAddr == None or AddrTableSize == None:
            return []

    socket_list = []
    for cnt in range(0,AddrTableSize):
        EntryAddress=AddrObjAddr + 4*cnt

        if not addr_space.is_valid_address(EntryAddress):
            continue

        TableEntry = read_value(addr_space, 'unsigned long', EntryAddress)
        if TableEntry == 0 or TableEntry == None:
            continue

        socket_list.append(TableEntry)
        next = read_obj(addr_space, types,
                        ['_ADDRESS_OBJECT', 'Next'], TableEntry)

        while next != 0x0:
            if not addr_space.is_valid_address(next):
                print "SocketList Truncated Invalid 0x%x"%next
                return socket_list
            socket_list.append(next)
            next = read_obj(addr_space, types,
                            ['_ADDRESS_OBJECT', 'Next'], next)

    return socket_list


def find_sockets(addr_space, types, symbol_table, base_addr):

    socket_list = []

    for offsets in module_versions:
        offsets = module_versions[offsets]
         
        socket_list = get_open_sockets(addr_space, types, symbol_table, base_addr, offsets['AddrObjTableOffset'][0], offsets['AddrObjTableSizeOffset'][0])
        if len(socket_list) > 0:
            return socket_list

    return socket_list


def socket_pid(addr_space, types, socket_vaddr):
    return read_obj(addr_space, types,
                    ['_ADDRESS_OBJECT', 'Pid'], socket_vaddr)

def socket_protocol(addr_space, types, socket_vaddr):
    return read_obj(addr_space, types,
                    ['_ADDRESS_OBJECT', 'Protocol'], socket_vaddr)

def socket_local_port(addr_space, types, socket_vaddr):
    return ntohs(read_obj(addr_space, types,
                    ['_ADDRESS_OBJECT', 'LocalPort'], socket_vaddr))

def socket_create_time(addr_space, types, socket_vaddr):
    (create_time_offset, tmp) = get_obj_offset(types, ['_ADDRESS_OBJECT', 'CreateTime'])    
    create_time     = read_time(addr_space, types, socket_vaddr + create_time_offset)
    if create_time == None:
        return None

    create_time     = windows_to_unix_time(create_time)
    return create_time
