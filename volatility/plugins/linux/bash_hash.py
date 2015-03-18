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
from operator import attrgetter
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.linux.common  as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid

bash_hash_vtypes_32 = {
    '_pathdata' : [ 8, {
    'path'  : [0x0, ['pointer', ['String', dict(length = 1024)]]],
    'flags': [0x4, ['int']],
    }],

    'bucket_contents' : [ 20, {
    'next' : [0x0, ['pointer', ['bucket_contents']]],
    'key'  : [0x4, ['pointer', ['String', dict(length = 1024)]]],
    'data' : [0x8, ['pointer', ['_pathdata']]],
    'times_found' : [16, ['int']],
    }],

    '_bash_hash_table': [ 0xc, {
    'bucket_array': [0x0, ['pointer', ['bucket_contents']]],
    'nbuckets': [0x4, ['int']],
    'nentries': [0x8, ['int']],
    }],
}

bash_hash_vtypes_64 = {
    '_pathdata' : [ 12, {
    'path'  : [0x0, ['pointer', ['String', dict(length = 1024)]]],
    'flags': [0x8, ['int']],
    }],

    'bucket_contents' : [ 32, {
    'next' : [0, ['pointer', ['bucket_contents']]],
    'key'  : [8, ['pointer', ['String', dict(length = 1024)]]],
    'data' : [16, ['pointer', ['_pathdata']]],
    'times_found' : [28, ['int']],
    }],

    '_bash_hash_table': [ 16, {
    'bucket_array': [0, ['pointer', ['bucket_contents']]],
    'nbuckets': [8, ['int']],
    'nentries': [12, ['int']],
    }],
}

class _bash_hash_table(obj.CType):
    
    def is_valid(self):
        if (not obj.CType.is_valid(self) or
                not self.bucket_array.is_valid() or 
                not self.nbuckets == 64 or
                not self.nentries > 1):
            return False

        return True
        
class BashHashTypes(obj.ProfileModification):
    conditions = {"os" : lambda x : x in ["linux"]}

    def modification(self, profile):       
        if profile.metadata.get('memory_model', '32bit') == "32bit":
            profile.vtypes.update(bash_hash_vtypes_32)
        else:
            profile.vtypes.update(bash_hash_vtypes_64)

        profile.object_classes.update({"_bash_hash_table": _bash_hash_table})

class linux_bash_hash(linux_pslist.linux_pslist):
    """Recover bash hash table from bash process memory"""

    def __init__(self, config, *args, **kwargs): 
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('SCAN_ALL', short_option = 'A', default = False, help = 'scan all processes, not just those named bash', action = 'store_true')    

    def calculate(self):
        linux_common.set_plugin_members(self)
    
        tasks = linux_pslist.linux_pslist(self._config).calculate()

        for task in tasks:
            proc_as = task.get_process_address_space()
            
            # In cases when mm is an invalid pointer 
            if not proc_as:
                continue

            # Do we scan everything or just /bin/bash instances?
            if not (self._config.SCAN_ALL or str(task.comm) == "bash"):
                continue

            for ent in task.bash_hash_entries():
                yield task, ent

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                       ("Name", str),
                       ("Hits", int),
                       ("Command", str),
                       ("Path", str)],
                        self.generator(data))

    def generator(self, data):
        for task, bucket in data:
            yield (0, [int(task.pid), str(task.comm),
                           int(bucket.times_found), 
                           str(bucket.key.dereference()),
                           str(bucket.data.path.dereference())])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Hits", "6"),
                                  ("Command", "25"),
                                  ("Full Path", "")])
                                    
        for task, bucket in data:
            self.table_row(outfd, task.pid, task.comm, 
                           bucket.times_found, 
                           str(bucket.key.dereference()),
                           str(bucket.data.path.dereference()))

