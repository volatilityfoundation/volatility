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

import volatility.plugins.linux.pslist as linux_pslist

class linux_pstree(linux_pslist.linux_pslist):
    '''Shows the parent/child relationship between processes'''

    def __init__(self, *args, **kwargs):
        self.procs = {}
        linux_pslist.linux_pslist.__init__(self, *args, **kwargs)

    def render_text(self, outfd, data):

        self.procs = {}

        outfd.write("{0:20s} {1:15s} {2:15s}\n".format("Name", "Pid", "Uid"))

        for task in data:

            self.recurse_task(outfd, task, 0)

    def recurse_task(self, outfd, task, level):

        if task.pid in self.procs:
            return

        if task.mm:
            proc_name = task.comm
        else:
            proc_name = "[" + task.comm + "]"

        proc_name = "." * level + proc_name

        outfd.write("{0:20s} {1:15s} {2:15s}\n".format(proc_name, str(task.pid), str(task.uid or '')))

        self.procs[task.pid] = 1

        for child in task.children.list_of_type("task_struct", "sibling"):

            self.recurse_task(outfd, child, level + 1)

