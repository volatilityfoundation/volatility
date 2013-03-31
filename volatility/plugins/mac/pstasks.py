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
import volatility.plugins.mac.pslist as pslist
import volatility.plugins.mac.common as common

class mac_tasks(pslist.mac_pslist):
    """ List Active Tasks """
    def calculate(self):
        common.set_plugin_members(self)
        
        tasksaddr = self.addr_space.profile.get_symbol("_tasks")
        queue_entry = obj.Object("queue_entry", offset = tasksaddr, vm = self.addr_space)

        seen = [tasksaddr]

        for task in queue_entry.walk_list(list_head = tasksaddr):
            if (task.bsd_info and task.obj_offset not in seen):
                proc = task.bsd_info.dereference_as("proc") 
                yield proc 
                seen.append(task.obj_offset)