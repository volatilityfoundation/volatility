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
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_library_list(linux_pslist.linux_pslist):
    """ Lists libraries loaded into a process """

    def calculate(self):
        linux_common.set_plugin_members(self)
   
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            for mapping in task.get_libdl_maps():
                if mapping.l_name == "" or mapping.l_addr == 0:
                    continue

                yield task, mapping

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Task", "16"),
                          ("Pid", "8"),
                          ("Load Address", "[addrpad]"),
                          ("Path", ""),
                          ])
  
        for task, mapping in data:
            self.table_row(outfd, task.comm, task.pid, mapping.l_addr, mapping.l_name)

