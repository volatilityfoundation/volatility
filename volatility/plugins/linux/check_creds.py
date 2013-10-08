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

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_check_creds(linux_pslist.linux_pslist):
    """Checks if any processes are sharing credential structures"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        if not self.profile.obj_has_member("task_struct", "cred"):
            debug.error("This command is not supported in this profile.")

        creds = {}

        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:

            cred_addr = task.cred.v()
            
            if not cred_addr in creds:
                creds[cred_addr] = []
                
            creds[cred_addr].append(task.pid)
    
        yield creds
            
    def render_text(self, outfd, data):
    
        self.table_header(outfd, [("PIDs", "8")]) 
                    
        # print out processes that are sharing cred structures              
        for htable in data:
    
            for (addr, pids) in htable.items():

                if len(pids) > 1:
                    pid_str = ""
                    for pid in pids:
                        pid_str = pid_str + "{0:d}, ".format(pid)
                    pid_str = pid_str[:-2]

                    self.table_row(outfd, pid_str)




