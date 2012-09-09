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
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

'''
The purpose of this plugin is to check if any processes are sharing 'cred' structures
In the beginning of the 2.6 series, the user ID and group ID were just simple integers
So rootkits could elevate the privleges of userland processes by setting these to 0 (root)
In later kernels, credentials are kept in a fairly complicated 'cred' structure
So now rootkits instead of allocating and setting their own 'cred' structure
Simply set a processes cred structure to be that of another root process that does not exit (usually init / pid 1)
So this plugins checks for any processes sharing 'cred' structures and reports them as the kernel would normally never do this
It finds a wide range of rootkits and rootkit activity and you can focus your investigation on elevated process (i.e. bash)
'''
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




