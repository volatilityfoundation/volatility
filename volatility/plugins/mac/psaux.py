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
import volatility.addrspace as addrspace
import volatility.plugins.mac.pslist as pslist
import volatility.plugins.mac.common as common

class mac_psaux(pslist.mac_pslist):
    """ Prints processes with arguments in userland (**argv) """

    def calculate(self):
        common.set_plugin_members(self)

        procs = pslist.mac_pslist.calculate(self)

        for proc in procs:
            yield proc

    def render_text(self, outfd, data):
        for proc in data:
            outfd.write("{0} | {1}\n".format(proc.p_pid, proc.get_task_name()))