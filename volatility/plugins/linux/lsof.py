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

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_lsof(linux_pslist.linux_pslist):
    """Lists open files"""

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            fds = task.files.get_fds()
            max_fds = task.files.get_max_fds()

            fds = obj.Object(theType = 'Array', offset = fds.obj_offset, vm = self.addr_space, targetType = 'Pointer', count = max_fds)

            for i in range(max_fds):
                if fds[i]:
                    filp = obj.Object('file', offset = fds[i], vm = self.addr_space)
                    yield (task, filp, i)

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Pid", "8"),
                                  ("FD", "8"),
                                  ("Path", "")])

        for (task, filp, fd) in data:
            self.table_row(outfd, task.pid, fd, linux_common.get_path(task, filp))
