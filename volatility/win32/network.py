# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

import volatility.win32 as win32
import volatility.obj as obj

module_versions_xp = {
'MP' : {
  'TCBTableOff' : [0x497e8],
  'SizeOff' : [0x3f7c8],
  'AddrObjTableOffset' : [0x48760],
  'AddrObjTableSizeOffset' : [0x48764],
},
'UP' : {
  'TCBTableOff' : [0x495e8],
  'SizeOff' : [0x3f5bc],
  'AddrObjTableOffset' : [0x48560],
  'AddrObjTableSizeOffset' : [0x48564],
},
'2180' : {
  'TCBTableOff' : [0x493e8],
  'SizeOff' : [0x3f3b0],
  'AddrObjTableOffset'  : [0x48360],
  'AddrObjTableSizeOffset' : [0x48364],
},
'3244' : {
  'TCBTableOff' : [0x496E8],
  'SizeOff' : [0x3F6BC],
  'AddrObjTableOffset'  : [0x48660],
  'AddrObjTableSizeOffset' : [0x48664],
},
'3394': {
  'TCBTableOff': [0x49768],
  'SizeOff': [0x3F73C],
  'AddrObjTableOffset': [0x486E0],
  'AddrObjTableSizeOffset': [0x486E4],
},
'5625' : {
  'TCBTableOff' : [0x49ae8],
  'SizeOff' : [0x3fac8],
  'AddrObjTableOffset'  : [0x48a60],
  'AddrObjTableSizeOffset' : [0x48a64],
},
'2111' : {
  'TCBTableOff' : [0x49A68],
  'SizeOff' : [0x3FA48],
  'AddrObjTableOffset'  : [0x489E0],
  'AddrObjTableSizeOffset' : [0x489E4],
},
}

module_versions_2003 = {
# w2003 sp0
'3790' : {
 'TCBTableOff' : [0x4c6c8],
 'SizeOff' : [0x4312c],
 'AddrObjTableOffset'  : [0x4bba0],
 'AddrObjTableSizeOffset' : [0x4bba4],
},
# w2003 sp1
'1830' : {
 'TCBTableOff' : [0x4e428],
 'SizeOff' : [0x44140],
 'AddrObjTableOffset'  : [0x4d4e4],
 'AddrObjTableSizeOffset' : [0x4d4e8],
},
# w2003 sp2
'3959' : {
 'TCBTableOff' : [0x7c548],
 'SizeOff' : [0x50308],
 'AddrObjTableOffset'  : [0x5ada4],
 'AddrObjTableSizeOffset' : [0x5ada8],
},
# w2003 sp2
'4573' : {
 'TCBTableOff' : [0x7f0ac],
 'SizeOff' : [0x52328],
 'AddrObjTableOffset'  : [0x5cf04],
 'AddrObjTableSizeOffset' : [0x5cf08],
},
# w2003 sp2 x64
'3959_x64' : { 
 'TCBTableOff' : [0x000c8d30],
 'SizeOff' : [0x0009b4a0],
 'AddrObjTableOffset'  : [0x000a4880],
 'AddrObjTableSizeOffset' : [0x000a4888],
},
# w2003 sp1 x64
'1830_x64' : { 
 'TCBTableOff' : [0x8f2d0],
 'SizeOff' : [0x861cc],
 'AddrObjTableOffset'  : [0x8c4c0],
 'AddrObjTableSizeOffset' : [0x8c4c8],
},
# w2003 sp2 x64 (unknown build number)
'unk_1_x64' : { 
 'TCBTableOff' : [0xCD2D8],
 'SizeOff' : [0x9E4A0],
 'AddrObjTableOffset'  : [0xa78E0],
 'AddrObjTableSizeOffset' : [0xa78E8],
},
}
 
## Define the maxiumum number of sockets that we expect to see on a given system. 
## Due to the way we currently iterate over possible offsets, its easy to pick 
## the wrong one and end up creating an array of up to 0xFFFFFFFF objects, even 
## though there's no possibility of ever having that many active at one time. 
## This can lead to a MemoryError, which is bad. The limit we've chosen (2 million) 
## is based on 65535 for TCP, 65535 for UDP, for each of up to 100 IP addresses;
## then rounded up to the nearest million. Its not perfect, but it should prevent
## memory errors until we redesign the way we find socket and connection objects.
MAX_SOCKETS = 2000000

def determine_connections(addr_space):
    """Determines all connections for each module"""
    all_modules = win32.modules.lsmod(addr_space)

    version = (addr_space.profile.metadata.get('major', 0),
               addr_space.profile.metadata.get('minor', 0))

    if version <= (5, 1):
        module_versions = module_versions_xp
    else:
        module_versions = module_versions_2003

    for m in all_modules:
        if str(m.BaseDllName).lower() == 'tcpip.sys':
            for attempt in module_versions:
                table_size = obj.Object(
                    "long",
                    offset = m.DllBase +
                             module_versions[attempt]['SizeOff'][0],
                    vm = addr_space)

                table_addr = obj.Object(
                    "address",
                    offset = m.DllBase +
                             module_versions[attempt]['TCBTableOff'][0],
                    vm = addr_space)

                if table_size > 0:
                    table = obj.Object("Array",
                        offset = table_addr, vm = addr_space,
                        count = table_size,
                        target = obj.Curry(obj.Pointer, '_TCPT_OBJECT'))

                    if table:
                        for entry in table:
                            conn = entry.dereference()
                            seen = set()
                            while conn.is_valid() and conn.obj_offset not in seen:
                                yield conn
                                seen.add(conn.obj_offset)
                                conn = conn.Next.dereference()

def determine_sockets(addr_space):
    """Determines all sockets for each module"""
    all_modules = win32.modules.lsmod(addr_space)

    if addr_space.profile.metadata.get('major', 0) <= 5.1 and addr_space.profile.metadata.get('minor', 0) == 1:
        module_versions = module_versions_xp
    else:
        module_versions = module_versions_2003

    for m in all_modules:
        if str(m.BaseDllName).lower() == 'tcpip.sys':
            for attempt in module_versions:
                table_size = obj.Object(
                    "unsigned long",
                    offset = m.DllBase +
                             module_versions[attempt]['AddrObjTableSizeOffset'][0],
                    vm = addr_space)

                table_addr = obj.Object(
                    "address",
                    offset = m.DllBase +
                             module_versions[attempt]['AddrObjTableOffset'][0],
                    vm = addr_space)

                if int(table_size) > 0 and int(table_size) < MAX_SOCKETS:
                    table = obj.Object("Array",
                        offset = table_addr, vm = addr_space,
                        count = table_size,
                        target = obj.Curry(obj.Pointer, "_ADDRESS_OBJECT"))

                    if table:
                        for entry in table:
                            sock = entry.dereference()
                            seen = set()
                            while sock.is_valid() and sock.obj_offset not in seen:
                                yield sock
                                seen.add(sock.obj_offset)
                                sock = sock.Next.dereference()
