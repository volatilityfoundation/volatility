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
@organization: Digital Forensics Solutions
"""

import volatility.plugins.linux.pslist as linux_pslist

class linux_psaux(linux_pslist.linux_pslist):
    '''Gathers processes along with full command line and start time'''

    def calculate(self):

        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:

            name = self.get_task_name(task)

            yield task, name

    def render_text(self, outfd, data):

        outfd.write("{1:6s} {2:6s} {0:64s}\n".format("Arguments", "Pid", "Uid"))

        for task, name in data:
            outfd.write("{1:6s} {2:6s} {0:64s} {3:35s}\n".format(name, str(task.pid), str(task.uid), self.get_task_start_time(task)))

    def get_task_name(self, task):

        if task.mm:
            # set the as with our new dtb so we can read from userland
            proc_as = task.get_process_address_space()

            # read argv from userland
            start = task.mm.arg_start.v()

            argv = proc_as.read(start, task.mm.arg_end - task.mm.arg_start)

            # split the \x00 buffer into args
            name = " ".join(argv.split("\x00"))

        else:
            # kernel thread
            name = "[" + task.comm + "]"

        return name
