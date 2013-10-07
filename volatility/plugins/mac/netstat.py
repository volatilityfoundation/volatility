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
import volatility.plugins.mac.lsof as lsof

class mac_netstat(lsof.mac_lsof):
    """ Lists active per-process network connections """

    def render_text(self, outfd, data):
        
        self.table_header(outfd, [("Proto", "6"),
                                  ("Local IP", "20"),
                                  ("Local Port", "6"),
                                  ("Remote IP", "20"),
                                  ("Remote Port", "6"),
                                  ("State", "10"),
                                  ("Process", "24")])
        
        for proc, i, fd, _path in data:
            if str(fd.f_fglob.fg_type or '') == 'DTYPE_SOCKET':
                socket = fd.f_fglob.fg_data.dereference_as("socket") 
                family = socket.family
    
                if family == 1:
                    upcb = socket.so_pcb.dereference_as("unpcb")
                    path = upcb.unp_addr.sun_path
                    outfd.write("UNIX {0}\n".format(path))
                elif family in [2, 30]:
                    proto = socket.protocol
                    state = socket.state
                   
                    (lip, lport, rip, rport) = socket.get_connection_info()
 
                    self.table_row(outfd, proto, lip, lport, rip, rport, state, "{}/{}".format(proc.p_comm, proc.p_pid))
                    

  
