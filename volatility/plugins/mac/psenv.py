# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

import volatility.plugins.mac.pstasks as pstasks
from volatility.renderers import TreeGrid

class mac_psenv(pstasks.mac_tasks):
    """ Prints processes with environment in user land (**envp) """

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                        ("Name", str),
                        ("Bits", str),
                        ("Arguments", str),
                        ], self.generator(data))

    def generator(self, data):
        for proc in data:
            yield(0, [
                    int(proc.p_pid),
                    str(proc.p_comm),
                    str(proc.task.map.pmap.pm_task_map),
                    str(proc.get_environment()),
                    ])

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Bits", "16"),
                                  ("Arguments", "")])
        for proc in data:
            self.table_row(outfd, 
                           proc.p_pid, 
                           proc.p_comm, 
                           str(proc.task.map.pmap.pm_task_map or '')[9:],
                           proc.get_environment())
