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
import volatility.plugins.mac.common as common

class mac_tasks(common.AbstractMacCommand):
    """ List Active Tasks """
    def calculate(self):
        common.set_plugin_members(self)
        
        tasksaddr = self.addr_space.profile.get_symbol("_tasks")
        queue_entry = obj.Object("queue_entry", offset = tasksaddr, vm = self.addr_space)

        seen = [tasksaddr]

        for task in queue_entry:
            if (task.bsd_info and task.obj_offset not in seen):
                yield task 
                seen.append(task.obj_offset)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                          ("Proc Name", "20"),
                          ("Proc Pid", "8")])

        for task in data:
            proc = task.bsd_info.dereference_as("proc")
            self.table_row(outfd, task.obj_offset,
                                  proc.p_comm,
                                  str(proc.p_pid))


