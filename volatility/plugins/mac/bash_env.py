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

import struct
from operator import attrgetter
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.mac.common  as mac_common
import volatility.plugins.mac.pstasks as mac_tasks
from volatility.renderers import TreeGrid

class mac_bash_env(mac_tasks.mac_tasks):
    """Recover bash's environment variables"""

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                        ("Name", str),
                        ("Vars", str),
                        ], self.generator(data))

    def generator(self, data):
        for task in data:
            varstr = ""

            for (key, val) in task.bash_environment():
                varstr = varstr + "%s=%s " % (key, val)

            yield(0, [
                  int(task.p_pid),
                  str(task.p_comm),
                  str(varstr),
                  ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Vars", "")])
                                    
        for task in data:
            varstr = ""
            for (key, val) in task.bash_environment():
                varstr = varstr + "%s=%s " % (key, val)
            self.table_row(outfd, task.p_pid, task.p_comm, varstr)
