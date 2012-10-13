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
import mac_pslist

class mac_psaux(mac_pslist.mac_pslist):

    def calculate(self):

        procs = mac_pslist.mac_pslist.calculate(self)

        for proc in procs:

            name = self.get_task_name(proc)

            yield proc, name

    def get_task_name(self, proc):

        task = obj.Object("task", offset=proc.task, vm=self.addr_space) 
        
        cr3  = task.map.pmap.pm_cr3

        proc_as = self.addr_space.__class__(self.addr_space.base, self.addr_space.get_config(), dtb = cr3) 

        argv = proc_as.read(proc.user_stack - proc.p_argslen, proc.p_argslen)

        name = " ".join(argv.split("\x00"))

        return name

    def render_text(self, outfd, data):
        
        for (proc, name) in data:

            outfd.write("%d | %s\n" % (proc.p_pid, name))




