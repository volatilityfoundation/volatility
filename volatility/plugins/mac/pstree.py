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
@organization: 
"""

import volatility.obj as obj
import volatility.plugins.mac.pslist as pslist
import volatility.plugins.mac.common as common

class mac_pstree(pslist.mac_pslist):
    """ Show parent/child relationship of processes """

    def render_text(self, outfd, data):
        self.procs_hash = {}
        self.procs_seen = {}

        outfd.write("{0:20s} {1:15s} {2:15s}\n".format("Name", "Pid", "Uid"))

        for proc in data:
            self.procs_hash[proc.p_pid] = proc

        for pid in sorted(self.procs_hash.keys()):
            proc = self.procs_hash[pid]
            self._recurse_task(outfd, proc, 0)

    def _recurse_task(self, outfd, proc, level):
        if proc.p_pid in self.procs_seen:
            return

        proc_name = common.get_string(proc.p_comm.obj_offset, self.addr_space)
        proc_name = "." * level + proc_name

        outfd.write("{0:20s} {1:15s} {2:15s}\n".format(proc_name, str(proc.p_pid), str(proc.p_ucred.cr_uid)))
  
        self.procs_seen[proc.p_pid] = 1
        
        proc = proc.p_children.lh_first
        if not proc.is_valid():
            return

        while 1:
            self._recurse_task(outfd, proc, level + 1)
            proc = proc.p_sibling.le_next
            if not proc:
                break
                






