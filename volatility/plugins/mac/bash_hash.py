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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import struct
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.mac.common as mac_common
import volatility.plugins.mac.pslist as mac_pslist
from volatility.renderers import TreeGrid

mac_bash_hash_vtypes = {
    'mac32_pathdata' : [ 8, {
    'path'  : [0x0, ['pointer', ['String', dict(length = 1024)]]],
    'flags': [0x4, ['int']],
    }],

    'mac32_envdata' : [ 8, {
    'name'   : [0x0, ['pointer', ['String', dict(length = 1024)]]],
    'value'  : [0x4, ['pointer', ['String', dict(length = 1024)]]],
    }],

    'mac32_bucket_contents' : [ 20, {
    'next' : [0x0, ['pointer', ['mac32_bucket_contents']]],
    'key'  : [0x4, ['pointer', ['String', dict(length = 1024)]]],
    'data' : [0x8, ['pointer', ['mac32_pathdata']]],
    'times_found' : [16, ['int']],
    }],

    'mac32_bash_hash_table': [ 0xc, {
    'bucket_array': [0x0, ['pointer', ['mac32_bucket_contents']]],
    'nbuckets': [0x4, ['int']],
    'nentries': [0x8, ['int']],
    }],
    
    'mac64_pathdata' : [ 12, {
    'path'  : [ 0, ['pointer', ['String', dict(length = 1024)]]],
    'flags' : [ 8, ['int']],
    }],

    'mac64_envdata' : [ 16, {
    'name'   : [0x0, ['pointer', ['String', dict(length = 1024)]]],
    'value'  : [0x8, ['pointer', ['String', dict(length = 1024)]]],
    }],

    'mac64_bucket_contents' : [ 32, {
    'next' : [0, ['pointer', ['mac64_bucket_contents']]],
    'key'  : [8, ['pointer', ['String', dict(length = 1024)]]],
    'data' : [16, ['pointer', ['mac64_pathdata']]],
    'times_found' : [28, ['int']],
    }],

    'mac64_bash_hash_table': [ 16, {
    'bucket_array': [0, ['pointer', ['mac64_bucket_contents']]],
    'nbuckets': [8, ['int']],
    'nentries': [12, ['int']],
    }],
}

class bash_funcs(obj.CType): 
    def __init__(self, ptr_size, theType, offset, vm, name = None, **kwargs):
        self.ptr_size = ptr_size
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

    @property
    def path(self):
        addr = self.m("path").obj_offset 
        addr = self.read_ptr(addr)

        ret = ""

        if addr:
            ret = self.obj_vm.read(addr, 256)
            if ret:
                idx = ret.find("\x00")
                if idx != -1:
                    ret = ret[:idx]

        return ret

    def next_bucket(self):  
        addr = self.m("next").obj_offset 
        addr = self.read_ptr(addr)
        
        if self.ptr_size == 32:
            ptype = "mac32_bucket_contents"
        else:
            ptype = "mac64_bucket_contents"

        return obj.Object(ptype, offset = addr, vm = self.obj_vm)

    @property
    def key(self):
        addr = self.m("key").obj_offset 
        addr = self.read_ptr(addr)
 
        ret = ""

        if addr:
            ret = self.obj_vm.read(addr, 256)
            if ret:
                idx = ret.find("\x00")
                if idx != -1:
                    ret = ret[:idx]
            else:
                ret = ""

        return ret

    @property
    def data(self):
        addr = self.m("data").obj_offset 
        addr = self.read_ptr(addr)

        if self.ptr_size == 32:
            ptype = "mac32_pathdata"
        else:
            ptype = "mac64_pathdata"

        return obj.Object(ptype, offset = addr, vm = self.obj_vm)

    @property
    def bucket_array(self):
        addr = self.m("bucket_array").obj_offset 
        return self.read_ptr(addr)
 
    def read_ptr_32(self, addr):
        addr = self.obj_vm.read(addr, 4)
        addr = struct.unpack("<I", addr)[0]
        return addr

    def read_ptr_64(self, addr):
        addr = self.obj_vm.read(addr, 8)
        addr = struct.unpack("<Q", addr)[0]
        return addr

    def read_ptr(self, addr):
        if self.ptr_size == 32:
            ret = self.read_ptr_32(addr)
        else:
            ret = self.read_ptr_64(addr)

        return ret

class mac64_bash_hash_table(bash_funcs):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        bash_funcs.__init__(self, 64, theType, offset, vm, name, **kwargs)    

    def is_valid(self):
        if (not obj.CType.is_valid(self) or
                not self.obj_vm.is_valid_address(self.bucket_array) or 
                not self.nbuckets == 64 or
                not self.nentries >= 0):
            return False

        return True
    
    def __iter__(self):
        if self.is_valid():
            bucket_array = obj.Object(theType="Array", targetType="Pointer", offset = self.bucket_array, vm = self.nbuckets.obj_vm, count = 64)
   
            for bucket_ptr in bucket_array:
                bucket = bucket_ptr.dereference_as("mac64_bucket_contents")
                seen = {}
                
                while bucket.is_valid() and bucket.v() not in seen:
                    yield bucket

                    seen[bucket.v()] = 1
                    bucket = bucket.next
 
class mac32_bash_hash_table(bash_funcs):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        bash_funcs.__init__(self, 32, theType, offset, vm, name, **kwargs)    

    def is_valid(self):
        if (not obj.CType.is_valid(self) or
                not self.obj_vm.is_valid_address(self.bucket_array) or 
                not self.nbuckets == 64 or
                not self.nentries > 1):
            return False

        return True
 
    def __iter__(self):
        if self.is_valid():
            bucket_array = obj.Object(theType="Array", targetType="Pointer", offset = self.bucket_array, vm = self.nbuckets.obj_vm, count = 64)
   
            for bucket_ptr in bucket_array:
                bucket = bucket_ptr.dereference_as("mac32_bucket_contents")
                while bucket.is_valid() and bucket.times_found > 0 and bucket.data.is_valid() and bucket.key != "":  
                    yield bucket

                    bucket = bucket.next
 

   
class mac64_pathdata(bash_funcs):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        bash_funcs.__init__(self, 64, theType, offset, vm, name, **kwargs)    

class mac32_pathdata(bash_funcs):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        bash_funcs.__init__(self, 32, theType, offset, vm, name, **kwargs)    
 
class mac64_bucket_contents(bash_funcs):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        bash_funcs.__init__(self, 64, theType, offset, vm, name, **kwargs)    

class mac32_bucket_contents(bash_funcs):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        bash_funcs.__init__(self, 32, theType, offset, vm, name, **kwargs)    
       
class MacBashHashTypes(obj.ProfileModification):
    conditions = {"os" : lambda x : x in ["mac"]}

    def modification(self, profile):       
        profile.vtypes.update(mac_bash_hash_vtypes)

        profile.object_classes.update({
                "mac32_bucket_contents" : mac32_bucket_contents,
                "mac64_bucket_contents" : mac64_bucket_contents,
                "mac32_pathdata"        : mac32_pathdata,
                "mac64_pathdata"        : mac64_pathdata, 
                "mac32_bash_hash_table" : mac32_bash_hash_table,
                "mac64_bash_hash_table" : mac64_bash_hash_table,
                })

class mac_bash_hash(mac_pslist.mac_pslist):
    """Recover bash hash table from bash process memory"""

    def __init__(self, config, *args, **kwargs): 
        mac_pslist.mac_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('SCAN_ALL', short_option = 'A', default = False, help = 'scan all processes, not just those named bash', action = 'store_true')    

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                            ("Name", str),
                            ("Hits", int),
                            ("Command", str),
                            ("Full Path", str),
                            ], self.generator(data))

    def generator(self, data):
        for task in data:
            # Do we scan everything or just /bin/bash instances?
            if not (self._config.SCAN_ALL or str(task.p_comm) == "bash"):
                continue

            for bucket in task.bash_hash_entries():
                yield (0, [
                    int(task.p_pid),
                    str(task.p_comm),
                    int(bucket.times_found),
                    str(bucket.key),
                    str(bucket.data.path),
                    ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Hits", "6"),
                                  ("Command", "25"),
                                  ("Full Path", "")])
                                    
        for task in data:
            # Do we scan everything or just /bin/bash instances?
            if not (self._config.SCAN_ALL or str(task.p_comm) == "bash"):
                continue

            for bucket in task.bash_hash_entries():
                self.table_row(outfd, task.p_pid, task.p_comm, 
                           bucket.times_found,
                           str(bucket.key),
                           str(bucket.data.path))

