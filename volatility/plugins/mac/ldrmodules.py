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

import volatility.obj as obj
import volatility.plugins.mac.common as mac_common
import volatility.plugins.mac.pslist as mac_pslist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_ldrmodules(mac_pslist.mac_pslist):
    """Compares the output of proc maps with the list of libraries from libdl"""

    def calculate(self):
        mac_common.set_plugin_members(self)

        procs = mac_pslist.mac_pslist(self._config).calculate()
        proc_maps = {}
        dl_maps   = {}
        seen_starts = []

        for task in procs:
            proc_maps[task.obj_offset] = {}
            proc_as = task.get_process_address_space()        

            for map in task.get_proc_maps():
                sig = proc_as.read(map.start, 4)
                
                if sig in ['\xce\xfa\xed\xfe', '\xcf\xfa\xed\xfe']:
                    prot = map.get_perms()
 
                    if prot in ["rw-", "r--"]:
                        continue 

                    fname = map.get_path()        
 
                    proc_maps[task.obj_offset][map.start.v()] = (task, proc_as, fname)

            dl_maps[task.obj_offset] = {}
            for so in task.get_dyld_maps():
                dl_maps[task.obj_offset][so.imageLoadAddress] = (task, proc_as, str(so.imageFilePath))
    
        for task_offset in dl_maps:
            for vm_start in dl_maps[task_offset]:
                seen_starts.append(vm_start)

                (task, proc_as, vm_name) = dl_maps[task_offset][vm_start] 
                yield (task_offset, task, proc_as, vm_start, vm_name, proc_maps, dl_maps)

        for task_offset in proc_maps:
            for vm_start in proc_maps[task_offset]:
                if vm_start in seen_starts:
                    continue

                (task, proc_as, vm_name) = proc_maps[task_offset][vm_start]
                yield (task_offset, task, proc_as, vm_start, vm_name, proc_maps, dl_maps)

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                        ("Name", str),
                        ("Start", Address),
                        ("File Path", str),
                        ("Kernel", str),
                        ("Dyld", str),
                        ], self.generator(data))

    def generator(self, data):
        for task_offset, task, proc_as, vm_start, map_name, proc_maps, dl_maps in data:
            if vm_start in proc_maps[task_offset]:
                pmaps = "True"
            else:
                pmaps = "False"

            if vm_start in dl_maps[task_offset]:
                dmaps = "True"
            else:
                dmaps = "False"

            yield(0, [
                int(task.p_pid),
                str(task.p_comm),
                Address(vm_start),
                str(map_name),
                str(pmaps),
                str(dmaps),
                ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"),
                                  ("Name", "16"),
                                  ("Start", "#018x"),
                                  ("File Path", "100"),                    
                                  ("Kernel", "6"),
                                  ("Dyld", "6"), 
                                ]) 

        for task_offset, task, proc_as, vm_start, map_name, proc_maps, dl_maps in data:
            if vm_start in proc_maps[task_offset]:
                pmaps = "True"
            else:
                pmaps = "False"

            if vm_start in dl_maps[task_offset]:
                dmaps = "True"
            else:
                dmaps = "False"

            self.table_row(outfd, 
                task.p_pid, 
                str(task.p_comm),
                vm_start,
                map_name,
                pmaps,
                dmaps)

