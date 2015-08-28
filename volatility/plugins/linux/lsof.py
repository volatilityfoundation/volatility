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
"""



import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers.basic import Address
from volatility.renderers import TreeGrid

class linux_lsof(linux_pslist.linux_pslist):
    """Lists file descriptors and their path"""

    def unified_output(self, data):
        return TreeGrid([("Offset",Address),
                         ("Name",str),
                        ("Pid", int),
                       ("FD", int),
                       ("Path", str)],
                        self.generator(data))

    def generator(self, data):
        for task in data:
            for filp, fd in task.lsof():
                yield (0, [Address(task.obj_offset),str(task.comm),int(task.pid), int(fd), str(linux_common.get_path(task, filp))])


    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset","#018x"),
                                  ("Name","30"),
                                  ("Pid", "8"),
                                  ("FD", "8"),
                                  ("Path", "")])

        for task in data:
            for filp, fd in task.lsof(): 
                self.table_row(outfd, Address(task.obj_offset), str(task.comm), task.pid, fd, linux_common.get_path(task, filp))