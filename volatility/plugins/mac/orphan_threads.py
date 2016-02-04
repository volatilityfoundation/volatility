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
import volatility.plugins.mac.pstasks as pstasks
import volatility.plugins.mac.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_orphan_threads(pstasks.mac_tasks):
    """Lists threads that don't map back to known modules/processes"""

    def unified_output(self, data):
        common.set_plugin_members(self)

        return TreeGrid([("PID",int),
                        ("Process Name", str),
                        ("Start Address", Address),
                        ("Mapping", str),
                        ("Name", str),
                        ("Status", str),
                        ], self.generator(data))

    def generator(self, data):
        (kstart, kend, kmods) = common.get_kernel_addrs_start_end(self)
        
        for proc in data:
            for thread in proc.threads():
                start = thread.continuation

                if start == 0:
                    continue

                (good, mapping) = common.is_in_kernel_or_module(start, kstart, kend, kmods)

                if not good:
                    mapping = "UNKNOWN"
                    for map in proc.get_proc_maps():
                        if map.links.start <= start <= map.links.end:
                            mapping = map.get_path()
                            if mapping == "":
                                mapping = map.get_special_path()
                       
                            good  = 1 
                            start = map.links.start
 
                if good:
                    status = "OK"
                else:
                    status = "UNKNOWN"

                name = ""
                if thread.uthread:
                    name_buf = self.addr_space.read(thread.uthread.dereference_as("uthread").pth_name, 256)
                    if name_buf:
                        idx = name_buf.find("\x00")
                        if idx != -1:
                            name_buf = name_buf[:idx]
                        
                        name = name_buf

                yield(0, [
                    int(proc.p_pid),
                    str(proc.p_comm),
                    Address(start),
                    str(mapping),
                    str(name),
                    str(status),
                    ])
 
    def render_text(self, outfd, data):
        common.set_plugin_members(self)

        self.table_header(outfd, [("PID","8"),
                                  ("Name", "16"),
                                  ("Start Address", "[addrpad]"),
                                  ("Mapping", "40"),
                                  ("Name", "40"),
                                  ("Status", ""),
                                 ])
 
        (kstart, kend, kmods) = common.get_kernel_addrs_start_end(self)
        
        for proc in data:
            for thread in proc.threads():
                start = thread.continuation
                if start == 0:
                    continue

                (good, mapping) = common.is_in_kernel_or_module(start, kstart, kend, kmods)
                if not good:
                    mapping = "UNKNOWN"
                    for map in proc.get_proc_maps():
                        if map.links.start <= start <= map.links.end:
                            mapping = map.get_path()
                            if mapping == "":
                                mapping = map.get_special_path()
                            good  = 1 
                            start = map.links.start

                status = "UNKNOWN"
                if good:
                    status = "OK"

                name = ""
                if thread.uthread:
                    name_buf = self.addr_space.read(thread.uthread.dereference_as("uthread").pth_name, 256)
                    if name_buf:
                        idx = name_buf.find("\x00")
                        if idx != -1:
                            name_buf = name_buf[:idx]
                        
                        name = name_buf

                self.table_row(outfd, proc.p_pid, proc.p_comm, start, mapping, name, status)
