# Volatility
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.plugins.linux.flags as linux_flags
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

PIDTYPE_PID = 0

# the < 2.6.24 processing is based on crash from redhat
class linux_pidhashtable(linux_pslist.linux_pslist):
    """Enumerates processes through the PID hash table"""

    def walk_tasks_for_pid(self, pid):

        if pid.obj_offset in self.seen_pids:
            return

        self.seen_pids[pid.obj_offset] = 1

        task_pid_off = self.profile.get_obj_offset("task_struct", "pids")
        pids_node_off = self.profile.get_obj_offset("pid_link", "node") 
        total_off = task_pid_off + pids_node_off

        for i in [PIDTYPE_PID]:

            task_ent = obj.Object("hlist_node", offset = pid.tasks[i].first, vm = self.addr_space)

            while task_ent.v():
         
                task = obj.Object("task_struct", offset = task_ent.obj_offset - total_off, vm = self.addr_space)

                yield task

                task_ent = task_ent.next

    def calculate_2_6_24(self):

        self.seen_pids = {}

        pidhash_shift = obj.Object("unsigned int", offset = self.get_profile_symbol("pidhash_shift"), vm = self.addr_space)
        pidhash_size = 1 << pidhash_shift 

        pidhash_addr = self.get_profile_symbol("pid_hash")
        pidhash_ptr = obj.Object("Pointer", offset = pidhash_addr, vm = self.addr_space)

        # pidhash is an array of hlist_heads
        pidhash = obj.Object(theType = 'Array', offset = pidhash_ptr, vm = self.addr_space, targetType = 'hlist_head', count = pidhash_size)

        for hlist in pidhash:
            
            # each entry in the hlist is a upid which is wrapped in a pid
            ent = hlist.first

            while ent:
    
                upid = linux_common.get_obj(self, ent.obj_offset, "upid", "pid_chain")
           
                while upid:

                    pid = linux_common.get_obj(self, upid.obj_offset, "pid", "numbers")

                    for task in self.walk_tasks_for_pid(pid):
                        yield task
                    
                    if not upid.pid_chain.next:
                        break
            
                    upid = linux_common.get_obj(self, upid.pid_chain.next, "upid", "pid_chain")
                    
                ent = ent.next

    def calculate(self):
        for task in self.calculate_2_6_24():
            yield task


