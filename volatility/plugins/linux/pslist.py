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
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_pslist(linux_common.AbstractLinuxCommand):
    """Gather active tasks by walking the task_struct->task list"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')

    @staticmethod
    def virtual_process_from_physical_offset(addr_space, offset):
        pspace = utils.load_as(addr_space.get_config(), astype = 'physical')
        task = obj.Object("task_struct", vm = pspace, offset = offset)
        parent = obj.Object("task_struct", vm = addr_space, offset = task.parent)
        
        for child in parent.children.list_of_type("task_struct", "sibling"):
            if child.obj_vm.vtop(child.obj_offset) == task.obj_offset:
                return child
        
        return obj.NoneObject("Unable to bounce back from task_struct->parent->task_struct")

    def allprocs(self):
        linux_common.set_plugin_members(self)

        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)

        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
            yield task

    def calculate(self):
        linux_common.set_plugin_members(self)

        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]

        for task in self.allprocs():
            if not pidlist or task.pid in pidlist:
                yield task

    def unified_output(self, data):
        return TreeGrid([("Offset", Address),
                       ("Name", str),
                       ("Pid", int),
                       ("Uid", str),
                       ("Gid", str),
                       ("DTB", Address),
                       ("StartTime", str)],
                        self.generator(data))

    def _get_task_vals(self, task):
        if task.parent.is_valid():
            ppid       = str(task.parent.pid)
        else:
            ppid       = "-"

        uid = task.uid
        if uid == None or uid > 10000:
            uid = "-"
        
        gid = task.gid
        if gid == None or gid > 100000:
            gid = "-"
    
        start_time = task.get_task_start_time()
        if start_time == None:
            start_time = "-"

        if task.mm.pgd == None:
            dtb = task.mm.pgd
        else:
            dtb = self.addr_space.vtop(task.mm.pgd) or task.mm.pgd

        task_offset = None
        if hasattr(self, "wants_physical") and task.obj_vm.base:
            task_offset = self.addr_space.vtop(task.obj_offset)
            
        if task_offset == None:
            task_offset = task.obj_offset

        return task_offset, dtb, ppid, uid, gid, str(start_time)

    def generator(self, data):
        for task in data:
            task_offset, dtb, ppid, uid, gid, start_time = self._get_task_vals(task)

            yield (0, [Address(task_offset),
                                  str(task.comm),
                                  int(task.pid),
                                  str(uid),
                                  str(gid), 
                                  Address(dtb),
                                  start_time])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Name", "20"),
                                  ("Pid", "15"),
                                  ("PPid", "15"),
                                  ("Uid", "15"),
                                  ("Gid", "6"),
                                  ("DTB", "[addrpad]"),
                                  ("Start Time", "")])
        for task in data:
            task_offset, dtb, ppid, uid, gid, start_time = self._get_task_vals(task)

            self.table_row(outfd, task_offset,
                                  task.comm,
                                  str(task.pid),
                                  str(ppid),
                                  str(uid),
                                  str(gid),
                                  dtb,
                                  str(start_time))

class linux_memmap(linux_pslist):
    """Dumps the memory map for linux tasks"""

    def unified_output(self, data):
        return TreeGrid([("Task", str),
                       ("Pid", int),
                       ("Virtual", Address),
                       ("Physical", Address),
                       ("Size", Address)],
                        self.generator(data))

    def generator(self, data):
        for task in data:
            task_space = task.get_process_address_space()

            pagedata = task_space.get_available_pages()
            if pagedata:
                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        yield (0, [str(task.comm), int(task.pid), Address(p[0]), Address(pa), Address(p[1])])
            else:
                yield(0, [str(task.comm), int(task.pid), Address(-1), Address(-1), Address(-1)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Task", "16"),
                                  ("Pid", "8"),
                                  ("Virtual", "[addrpad]"),
                                  ("Physical", "[addrpad]"),
                                  ("Size", "[addr]")])

        for task in data:
            task_space = task.get_process_address_space()

            pagedata = task_space.get_available_pages()
            if pagedata:
                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        self.table_row(outfd, task.comm, task.pid, p[0], pa, p[1])
                    #else:
                    #    outfd.write("0x{0:10x} 0x000000     0x{1:12x}\n".format(p[0], p[1]))
            else:
                outfd.write("Unable to read pages for {0} pid {1}.\n".format(task.comm, task.pid))
