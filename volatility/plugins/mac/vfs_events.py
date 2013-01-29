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

class mac_vfs_events(common.AbstractMacCommand):
    """ Lists Mac VFS Events """

    def calculate(self):
        common.set_plugin_members(self)

        list_head_addr = self.get_profile_symbol("_kfse_list_head")
        list_head = obj.Object("kfse_list", offset = list_head_addr, vm = self.addr_space)
        cur = list_head.lh_first

        while cur:
            s = common.get_string(cur.str, self.addr_space)
            yield (cur.str, s, cur.len) 
            cur = cur.kevent_list.le_next

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Address", "[addrpad]"), ("Name", "20"), ("Slen", "")])
        for (address, name, slen) in data:
            self.table_row(outfd, address, name, slen)
        

