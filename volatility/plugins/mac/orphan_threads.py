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

class mac_orphan_threads(pstasks.mac_tasks):
    """ Lists per-process opened files """

    def render_text(self, outfd, data):
        common.set_plugin_members(self)

        self.table_header(outfd, [("PID","8"),
                                  ("Name", "16"),
                                  ("Start Address", "[addrpad]"),
                                  ("Mapping", "40"),
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
 
                if good:
                    status = "OK"
                else:
                    status = "UNKNOWN"

                self.table_row(outfd, proc.p_pid, proc.p_comm, start, mapping, status)

 
