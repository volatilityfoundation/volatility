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

import volatility.plugins.mac.pslist as pslist
import volatility.obj as obj
import volatility.plugins.mac.common as common

class mac_list_sessions(pslist.mac_pslist):
    """ Enumerates sessions """

    def calculate(self):
        common.set_plugin_members(self)
            
        shash_addr = self.addr_space.profile.get_symbol("_sesshash") 
        shash = obj.Object("unsigned long", offset = shash_addr, vm = self.addr_space)

        shashtbl_addr = self.addr_space.profile.get_symbol("_sesshashtbl")
        shashtbl_ptr = obj.Object("Pointer", offset = shashtbl_addr, vm = self.addr_space)
        shash_array = obj.Object(theType = "Array", targetType = "sesshashhead", count = shash + 1, vm = self.addr_space, offset = shashtbl_ptr)
    
        for sess in shash_array:
            s = sess.lh_first
    
            while s:
                yield s                
                s = s.s_hash.le_next

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Leader (Pid)",  "8"),
                                  ("Leader (Name)", "20"),
                                  ("Login Name", "25")])

        for sess in data:
            if sess.s_leader:
                pid  = sess.s_leader.p_pid
                pname = sess.s_leader.p_comm
            else:
                pid = -1
                pname = "<INVALID LEADER>"
                    
            self.table_row(outfd, pid, pname, sess.s_login)

