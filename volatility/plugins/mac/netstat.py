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

tcp_states = ("",
              "ESTABLISHED",
              "SYN_SENT",
              "SYN_RECV",
              "FIN_WAIT1",
              "FIN_WAIT2",
              "TIME_WAIT",
              "CLOSE",
              "CLOSE_WAIT",
              "LAST_ACK",
              "LISTEN",
              "CLOSING")

class mac_netstat(lsof.mac_lsof):
    """ Lists active per-process network connections """

    def render_text(self, outfd, data):
        for _proc, i, fd, _path in data:
            if str(fd.f_fglob.fg_type or '') == 'DTYPE_SOCKET':
                socket = fd.f_fglob.fg_data.dereference_as("socket") 
                family = socket.so_proto.pr_domain.dom_family
    
                (lip, lport, rip, rport) = ("", "", "", "")

                if family == 1:
                    upcb = socket.so_pcb.dereference_as("unpcb")
                    path = upcb.unp_addr.sun_path
                    outfd.write("UNIX {0}\n".format(path))
                elif family in [2, 30]:
                    ipcb = socket.so_pcb.dereference_as("inpcb")
                    (proto, state) = self.get_proto(socket.so_proto.pr_protocol)
                    if family == 2:
                        (lip, lport, rip, rport) = self.parse_ipv4(socket, ipcb, proto)
                        outfd.write("{0} {1}:{2} {3}:{4} {5}\n".format(proto, lip, lport, rip, rport, state))
                    else:
                        (lip, lport, rip, rport) = self.parse_ipv6(socket, ipcb, proto) 
                        outfd.write("{0} {1}:{2} {3}:{4} {5}\n".format(proto, lip, lport, rip, rport, state))

    def get_tcp_state(self, state):
        return tcp_states[state]

    def get_proto(self, proto):
        if proto == 6:
            ret = ("TCP", self.get_tcp_state(proto))

        elif proto ==  17:
            ret = ("UDP", "")

        else:
            ret = ("", "")

        return ret

    def parse_ipv4(self, socket, pcb, proto):
        lip = pcb.inp_dependladdr.inp46_local.ia46_addr4.s_addr.v()    
        lport = pcb.inp_lport 

        rip = pcb.inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr.v()
        rport = pcb.inp_fport 
        
        return (lip, lport, rip, rport)

    def parse_ipv6(self, socket, pcb, proto):
        lip = pcb.inp_dependladdr.inp6_local.__u6_addr.v()
        lport = pcb.inp_lport 

        rip = pcb.inp_dependfaddr.inp6_foreign.__u6_addr.v() 
        rport = pcb.inp_fport 

        return (lip, lport, rip, rport)
