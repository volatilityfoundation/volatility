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

import volatility.obj as obj
import volatility.plugins.linux.pslist as linux_pslist
import time

class linux_psaux(linux_pslist.linux_pslist):
    ''' gathers processes along with full command line and start time '''

    def calculate(self):

        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:

            name = self.get_task_name(task)
            start_time = self.calc_time(task.start_time.tv_sec)

            yield task, name, start_time

    def render_text(self, outfd, data):

        outfd.write("{1:6s} {2:6s} {0:64s}\n".format("Arguments", "Pid", "Uid"))

        for task, name, _start_time in data:
            outfd.write("{1:6s} {2:6s} {0:64s}\n".format(name, str(task.pid), str(task.uid)))

    def calc_time(self, start_offset):

        wall_to_monotonic = obj.Object("timespec", offset = self.get_profile_symbol("wall_to_monotonic"), vm = self.addr_space)
        xtime = obj.Object("timespec", offset = self.get_profile_symbol("xtime"), vm = self.addr_space)

        # this emualtes old code I had from the kerenl
        boot_time = wall_to_monotonic.tv_sec + xtime.tv_sec
        tspec = boot_time - start_offset
        etime = tspec# * 1000000000


        return time.ctime(etime)

    def get_task_name(self, task):

        if task.mm:
            # set the as with our new dtb so we can read from userland
            proc_as = task.get_process_address_space()

            # read argv from userland
            start = task.mm.arg_start.v()

            # It seems that on 64 bit systems this parameter is
            # shifted to the base of the stack.
            if task.obj_vm.profile.metadata.get("memory_model") == "64bit":
                start += 0x7fff00000000

            argv = proc_as.read(start, task.mm.arg_end - task.mm.arg_start)

            # split the \x00 buffer into args
            name = " ".join(argv.split("\x00"))

        else:
            # kernel thread
            name = "[" + task.comm + "]"

        return name
