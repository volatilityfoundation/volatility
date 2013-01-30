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
import volatility.plugins.mac.common as common

class mac_ls_logins(common.AbstractMacCommand):
    """ Lists login contexts """

    def calculate(self):
        common.set_plugin_members(self)
        
        allctx_addr = self.get_profile_symbol("_alllctx") 
        lctx_list = obj.Object("lctxlist", offset = allctx_addr, vm = self.addr_space)
        lctx = lctx_list.lh_first
        
        while lctx:
            procs = []
            lid = lctx.lc_id

            p = lctx.lc_members.lh_first
            while p:
                procs.append((p.p_pid, proc.p_comm))
                p = p.p_list.le_next

            yield (lids, procs)
            lctx = lctx.lc_list.le_next

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Lid", "8"), ("Pid", "8"), ("Name", "")])
        for (lid, procs) in data:
            if procs:
                for (pid, name) in procs:
                    self.table_row(outfd, lid, pid, name)
            else:
                # a lid with no procs 
                self.table_row(outfd, lid, "", "")