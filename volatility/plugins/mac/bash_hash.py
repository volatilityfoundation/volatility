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

class mac_bash_hash(mac_pslist.mac_pslist):
    """Recover bash hash table from bash process memory"""

    def __init__(self, config, *args, **kwargs): 
        mac_pslist.mac_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('SCAN_ALL', short_option = 'A', default = False, help = 'scan all processes, not just those named bash', action = 'store_true')    

    def calculate(self):
        mac_common.set_plugin_members(self)
    
        tasks = mac_pslist.mac_pslist(self._config).calculate()

        nbuckets_offset = self.addr_space.profile.get_obj_offset("_bash_hash_table", "nbuckets") 

        for task in tasks:
            proc_as = task.get_process_address_space()
            
            # In cases when mm is an invalid pointer 
            if not proc_as:
                continue

            # Do we scan everything or just /bin/bash instances?
            if not (self._config.SCAN_ALL or str(task.p_comm) == "bash"):
                continue


            bit_string = str(task.task.map.pmap.pm_task_map or '')[9:]
            if bit_string.find("64BIT") == -1:
                addr_type = "unsigned int"
            else:
                addr_type = "unsigned long long"

            proc_as = task.get_process_address_space()

            for map in task.get_proc_maps():
                if map.get_path() != "":
                    continue

                off = map.start

                while off < map.end:
                    # test the number of buckets
                    dr = proc_as.read(off + nbuckets_offset, 4)
                    if dr == None:
                        new_off = (off & ~0xfff) + 0xfff + 1
                        off = new_off
                        continue

                    test = struct.unpack("<I", dr)[0]
                    if test != 64:
                        off = off + 1
                        continue

                    htable = obj.Object("_bash_hash_table", offset = off, vm = proc_as)
                    
                    if htable.is_valid():
                        bucket_array = obj.Object(theType="Array", targetType=addr_type, offset = htable.bucket_array, vm = htable.nbuckets.obj_vm, count = 64)

                        for bucket_ptr in bucket_array:
                            bucket = obj.Object("bucket_contents", offset = bucket_ptr, vm = htable.nbuckets.obj_vm)
                            while bucket.times_found > 0 and bucket.data.is_valid() and bucket.key.is_valid():  
                                pdata = bucket.data 

                                if pdata.path.is_valid() and (0 <= pdata.flags <= 2):
                                    yield task, bucket

                                bucket = bucket.next
                    
                    off = off + 1

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Hits", "6"),
                                  ("Command", "25"),
                                  ("Full Path", "")])
                                    
        for task, bucket in data:
            self.table_row(outfd, task.p_pid, task.p_comm, 
                           bucket.times_found,
                           str(bucket.key.dereference()),
                           str(bucket.data.path.dereference()))


