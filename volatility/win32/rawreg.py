# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

#pylint: disable-msg=C0111

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      bdolangavitt@wesleyan.edu
"""

import volatility.debug as debug
import volatility.obj as obj
import struct

ROOT_INDEX = 0x20
LH_SIG = "lh"
LF_SIG = "lf"
RI_SIG = "ri"
NK_SIG = "nk"
VK_SIG = "vk"

BIG_DATA_MAGIC = 0x3fd8


KEY_FLAGS = {
    "KEY_IS_VOLATILE"   : 0x01,
    "KEY_HIVE_EXIT"     : 0x02,
    "KEY_HIVE_ENTRY"    : 0x04,
    "KEY_NO_DELETE"     : 0x08,
    "KEY_SYM_LINK"      : 0x10,
    "KEY_COMP_NAME"     : 0x20,
    "KEY_PREFEF_HANDLE" : 0x40,
    "KEY_VIRT_MIRRORED" : 0x80,
    "KEY_VIRT_TARGET"   : 0x100,
    "KEY_VIRTUAL_STORE" : 0x200,
}

VALUE_TYPES = dict(enumerate([
    "REG_NONE",
    "REG_SZ",
    "REG_EXPAND_SZ",
    "REG_BINARY",
    "REG_DWORD",
    "REG_DWORD_BIG_ENDIAN",
    "REG_LINK",
    "REG_MULTI_SZ",
    "REG_RESOURCE_LIST",
    "REG_FULL_RESOURCE_DESCRIPTOR",
    "REG_RESOURCE_REQUIREMENTS_LIST",
    "REG_QWORD",
]))

def get_root(address_space, stable = True):
    if stable:
        return obj.Object("_CM_KEY_NODE", ROOT_INDEX, address_space)
    else:
        return obj.Object("_CM_KEY_NODE", ROOT_INDEX | 0x80000000, address_space)

def open_key(root, key):
    if key == []:
        return root

    if not root.is_valid():
        return None

    keyname = key.pop(0)
    for s in subkeys(root):
        if s.Name.upper() == keyname.upper():
            return open_key(s, key)
    debug.debug("Couldn't find subkey {0} of {1}".format(keyname, root.Name), 1)
    return obj.NoneObject("Couldn't find subkey {0} of {1}".format(keyname, root.Name))

def read_sklist(sk):
    if (sk.Signature.v() == LH_SIG or
        sk.Signature.v() == LF_SIG):
        for i in sk.List:
            yield i

    elif sk.Signature.v() == RI_SIG:
        for i in range(sk.Count):
            # Read and dereference the pointer
            ptr_off = sk.List.obj_offset + (i * 4)
            if not sk.obj_vm.is_valid_address(ptr_off):
                continue
            ssk_off = obj.Object("unsigned int", ptr_off, sk.obj_vm)
            if not sk.obj_vm.is_valid_address(ssk_off):
                continue

            ssk = obj.Object("_CM_KEY_INDEX", ssk_off, sk.obj_vm)
            
            # this protects against a cycle seen in win10x86_14393 where
            # one of a key's subkey entries pointed back at itself
            if ssk == sk:
                break
                
            for i in read_sklist(ssk):
                yield i

# Note: had to change SubKeyLists to be array of 2 pointers in vtypes.py
def subkeys(key):
    if not key.is_valid():
        return

    for index in range(2):
        if int(key.SubKeyCounts[index]) > 0:
            sk_off = key.SubKeyLists[index]
            sk = obj.Object("_CM_KEY_INDEX", sk_off, key.obj_vm)
            if not sk or not sk.is_valid():
                pass
            else:
                for i in read_sklist(sk):
                    if i.Signature.v() == NK_SIG and i.Parent.dereference().Name == key.Name:
                        yield i

def values(key):
    return [ v for v in key.ValueList.List.dereference()
             if v.Signature.v() == VK_SIG ]

def key_flags(key):
    return [ k for k in KEY_FLAGS if key.Flags & KEY_FLAGS[k] ]

value_formats = {"REG_DWORD": "<L",
                 "REG_DWORD_BIG_ENDIAN": ">L",
                 "REG_QWORD": "<Q"}

def value_data(val):
    inline = val.DataLength & 0x80000000

    if inline:
        inline_len = val.DataLength & 0x7FFFFFFF
        if inline_len == 0 or inline_len > 4:
            valdata = None
        else:
            valdata = val.obj_vm.read(val.Data.obj_offset, inline_len)

    elif val.obj_vm.hive.Version == 5 and val.DataLength > 0x4000:
        # Value is a BIG_DATA block, stored in chunked format
        datalen = val.DataLength
        big_data = obj.Object("_CM_BIG_DATA", val.Data, val.obj_vm)
        valdata = ""
        thelist = []
        if not big_data.Count or big_data.Count > 0x80000000: 
            thelist = []
        else:
            for i in range(big_data.Count):
                ptr_off = big_data.List + (i * 4)
                chunk_addr = obj.Object("unsigned int", ptr_off, val.obj_vm)
                if not val.obj_vm.is_valid_address(chunk_addr):
                    continue
                thelist.append(chunk_addr)
        
        for chunk in thelist:
            amount_to_read = min(BIG_DATA_MAGIC, datalen)
            chunk_data = val.obj_vm.read(chunk, amount_to_read)
            if not chunk_data:
                valdata = None
                break
            valdata += chunk_data
            datalen -= amount_to_read
    else:
        valdata = val.obj_vm.read(val.Data, val.DataLength)

    valtype = VALUE_TYPES.get(val.Type.v(), "REG_UNKNOWN")
    if valdata == None:
        return (valtype, obj.NoneObject("Value data is unreadable"))
    if valtype in ["REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_QWORD"]:
        if len(valdata) != struct.calcsize(value_formats[valtype]):
            return (valtype, obj.NoneObject("Value data did not match the expected data size for a {0}".format(valtype)))

    if valtype in ["REG_SZ", "REG_EXPAND_SZ", "REG_LINK"]:
        valdata = valdata.decode('utf-16-le', "ignore")
    elif valtype == "REG_MULTI_SZ":
        valdata = valdata.decode('utf-16-le', "ignore").split('\0')
    elif valtype in ["REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_QWORD"]:
        valdata = struct.unpack(value_formats[valtype], valdata)[0]
    return (valtype, valdata)

def walk(root):
    yield root
    for k in subkeys(root):
        for j in walk(k):
            yield j
