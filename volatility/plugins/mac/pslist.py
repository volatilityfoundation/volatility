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
import volatility.obj   as obj
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.mac.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_pslist(common.AbstractMacCommand):
    """ List Running Processes """

    def __init__(self, config, *args, **kwargs):
        common.AbstractMacCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID', short_option = 'p', default = None, help = 'Operate on these Process IDs (comma-separated)', action = 'store', type = 'str')
        self._config.add_option('TASK', short_option = 'T', default = None, help = 'Operate on this process (virtual address from mac_psxview)', action = 'store', type = 'str')

    @staticmethod
    def virtual_process_from_physical_offset(addr_space, offset):
        pspace = utils.load_as(addr_space.get_config(), astype = 'physical')
        proc = obj.Object("proc", vm = pspace,     offset = offset)
        task = obj.Object("task", vm = addr_space, offset = proc.task)

        return task.bsd_info.dereference_as("proc")

    def allprocs(self):
        p = self.addr_space.profile.get_symbol("_allproc")

        procsaddr = obj.Object("proclist", offset = p, vm = self.addr_space)
        proc = obj.Object("proc", offset = procsaddr.lh_first, vm = self.addr_space)
        seen = []

        while proc.is_valid():
    
            if proc.obj_offset in seen:
                debug.warning("Recursive process list detected (a result of non-atomic acquisition). Use mac_tasks or mac_psxview)")
                break
            else:
                seen.append(proc.obj_offset)

            yield proc 

            proc = proc.p_list.le_next.dereference()

    def calculate(self):
        common.set_plugin_members(self)

        if self._config.TASK:
            task_addr = self._config.TASK
        
            try:
                task_addr = int(task_addr, 16)
            except TypeError:
                debug.error("Invalid task address given. Must be address in hex.")

            yield obj.Object("proc", offset = task_addr, vm = self.addr_space)  
        else:
            pidlist = None
            try:
                if self._config.PID:
                    pidlist = [int(p) for p in self._config.PID.split(',')]
            except:
                pass
            
            for proc in self.allprocs():
                if not pidlist or proc.p_pid in pidlist:
                    yield proc 

    def unified_output(self, data):
        return TreeGrid([("Offset (V)", Address),
                                  ("Name", str),
                                  ("PID", int),
                                  ("Uid", int ),
                                  ("Gid", int),
                                  ("PGID", int),
                                  ("Bits", str),
                                  ("DTB", Address),
                                  ("Start time", str),
                                  ("PPID", int),
                                  ], self.generator(data))
    def generator(self, data):
        for proc in data:
            if not proc.is_valid() or len(proc.p_comm) == 0:
                continue

            # Strip the "TASK_MAP_" prefix from the enumeration 
            bit_string = str(proc.task.map.pmap.pm_task_map or '')[9:]

            yield (0, [
                       Address(proc.v()),
                       str(proc.p_comm),
                       int(proc.p_pid),
                       int(proc.p_uid),
                       int(proc.p_gid),
                       int(proc.p_pgrpid),
                       str(bit_string),
                       Address(proc.task.dereference_as("task").map.pmap.pm_cr3),
                       str(proc.start_time()),
                       int(proc.p_ppid),
                       ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                          ("Name", "20"),
                          ("Pid", "8"),
                          ("Uid", "8"),
                          ("Gid", "8"),
                          ("PGID", "8"),
                          ("Bits", "12"),
                          ("DTB", "#018x"),
                          ("Start Time", ""),
                          ("Ppid", "8"),
                          ])

        for proc in data:
            if not proc.is_valid() or len(proc.p_comm) == 0:
                continue

            # Strip the "TASK_MAP_" prefix from the enumeration 
            bit_string = str(proc.task.map.pmap.pm_task_map or '')[9:]

            self.table_row(outfd, proc.v(),
                                  proc.p_comm,
                                  str(proc.p_pid),
                                  str(proc.p_uid),
                                  str(proc.p_gid),
                                  str(proc.p_pgrpid),
                                  bit_string,
                                  proc.task.dereference_as("task").map.pmap.pm_cr3,
                                  proc.start_time(),
                                  str(proc.p_ppid))
