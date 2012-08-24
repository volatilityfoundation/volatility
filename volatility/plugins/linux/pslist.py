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
import volatility.plugins.linux.common as linux_common

import time

class linux_pslist(linux_common.AbstractLinuxCommand):
    """Gather active tasks by walking the task_struct->task list"""

    @staticmethod
    def register_options(config):
        linux_common.AbstractLinuxCommand.register_options(config)
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')

    def calculate(self):
        init_task_addr = self.get_profile_symbol("init_task")

        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)

        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]

        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:

            if not pidlist or task.pid in pidlist:
            
                yield task

    ## FIXME: This currently returns using localtime, we should probably use UTC?
    def start_time(self, task):

        start_time  = task.start_time
        
        start_secs = start_time.tv_sec + (start_time.tv_nsec / linux_common.nsecs_per / 100)
        
        sec = linux_common.get_boot_time(self) + start_secs

        return time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(sec))

    def render_text(self, outfd, data):

        outfd.write("{0:8s} {1:20s} {2:15s} {3:15s} {4:35s}\n".format(
            "Offset", "Name", "Pid", "Uid", "Start Time"))

        for task in data:
            outfd.write("0x{0:08x} {1:20s} {2:15s} {3:15s} {4:35s}\n".format(
                task.obj_offset, task.comm, str(task.pid), str(task.uid), self.start_time(task)))

class linux_memmap(linux_pslist):
    """Dumps the memory map for linux tasks."""

    def render_text(self, outfd, data):
        first = True
        for task in data:
            if not first:
                outfd.write("*" * 72 + "\n")

            task_space = task.get_process_address_space()
            outfd.write("{0} pid: {1:6}\n".format(task.comm, task.pid))
            first = False

            pagedata = task_space.get_available_pages()
            if pagedata:
                outfd.write("{0:12} {1:12} {2:12}\n".format('Virtual', 'Physical', 'Size'))

                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        outfd.write("0x{0:010x} 0x{1:010x} 0x{2:012x}\n".format(p[0], pa, p[1]))
                    #else:
                    #    outfd.write("0x{0:10x} 0x000000     0x{1:12x}\n".format(p[0], p[1]))
            else:
                outfd.write("Unable to read pages for task.\n")

