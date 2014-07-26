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
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_ldrmodules(linux_pslist.linux_pslist):
    """Compares the output of proc maps with the list of libraries from libdl"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        procs = linux_pslist.linux_pslist(self._config).calculate()
        
        for task in procs:
            proc_maps = {}
            dl_maps   = {}
            seen_starts = {}

            proc_as = task.get_process_address_space()        

            # get libraries from proc_maps
            for vma in task.get_proc_maps():
                sig = proc_as.read(vma.vm_start, 4)
                
                if sig == "\x7fELF":
                    flags = str(vma.vm_flags)
           
                    if flags in ["rw-", "r--"]:
                        continue 

                    fname = vma.vm_name(task)

                    if fname == "[vdso]":
                        continue

                    start = vma.vm_start.v()

                    proc_maps[start]   = fname
                    seen_starts[start] = 1   

            # get libraries from userland
            for so in task.get_libdl_maps():
                if so.l_addr == 0x0 or len(str(so.l_name)) == 0:
                    continue
    
                start = so.l_addr.v()

                dl_maps[start] = str(so.l_name)
                seen_starts[start] = 1

            for start in seen_starts:
                vm_name = ""
                
                if start in proc_maps:    
                    pmaps = "True"
                    vm_name = proc_maps[start]
                else:
                    pmaps = "False"

                if start in dl_maps:
                    dmaps = "True"
                    
                    # we prefer the name from proc_maps as it is within kernel memory
                    if vm_name == "":
                        vm_name = dl_maps[start]
                else:
                    dmaps = "False"

                yield (task, start, vm_name, pmaps, dmaps)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"),
                                  ("Name", "16"),
                                  ("Start", "#018x"),
                                  ("File Path", "50"),                    
                                  ("Kernel", "6"),
                                  ("Libc", "6"), 
                                ]) 

        for task, vm_start, vma_name, pmaps, dmaps in data:
            self.table_row(outfd, 
                task.pid, 
                str(task.comm),
                vm_start,
                vma_name,
                pmaps,
                dmaps)



