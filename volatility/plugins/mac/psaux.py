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

import volatility.plugins.mac.pstasks as pstasks

class mac_psaux(pstasks.mac_tasks):
    """ Prints processes with arguments in user land (**argv) """

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Bits", "16"),
                                  ("Stack", "#018x"),
                                  ("Length", "8"),
                                  ("Argc", "8"),
                                  ("Arguments", "")])
        for proc in data:
            self.table_row(outfd, 
                           proc.p_pid, 
                           proc.p_comm, 
                           str(proc.task.map.pmap.pm_task_map)[9:],
                           proc.user_stack,
                           proc.p_argslen,
                           proc.p_argc,
                           proc.get_arguments())