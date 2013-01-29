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

import volatility.plugins.mac.pslist as pslist
import volatility.obj as obj
import volatility.plugins.mac.common as common

class mac_list_sessions(pslist.mac_pslist):
    """ Enumerates sessions """

    def calculate(self):
        common.set_plugin_members(self)
            
        shash_addr = self.get_profile_symbol("_sesshash") 
        shash = obj.Object("unsigned long", offset = shash_addr, vm = self.addr_space)

        shashtbl_addr = self.get_profile_symbol("_sesshashtbl")
        shashtbl_ptr = obj.Object("Pointer", offset=shashtbl_addr, vm = self.addr_space)
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
                pname = common.get_string(sess.s_leader.p_comm.obj_offset, self.addr_space)
            else:
                pid = -1
                pname = "<INVALID LEADER>"
        
            lname = sess.s_login
            
            self.table_row(outfd, pid, pname, lname)
                    

