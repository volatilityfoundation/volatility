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
import datetime
import volatility.obj as obj
import volatility.plugins.mac.common as common

class mac_route(common.AbstractMacCommand):
    """ Prints the routing table """

    def get_table(self, tbl):
        rnh = tbl #obj.Object("radix_node", offset=tbl.v(), vm=self.addr_space)
        rn = rnh.rnh_treetop
        
        while rn.rn_bit >= 0:
            rn = rn.rn_u.rn_node.rn_L

        rnhash = {}

        while 1:
            base = rn
            
            if rn in rnhash:
                break

            rnhash[rn] = 1

            while rn.rn_parent.rn_u.rn_node.rn_R == rn and rn.rn_flags & 2 == 0:
                rn = rn.rn_parent

            rn = rn.rn_parent.rn_u.rn_node.rn_R

            while rn.rn_bit >= 0:
                rn = rn.rn_u.rn_node.rn_L

            nextptr = rn

            while base.v() != 0:
    
                rn = base
                base = rn.rn_u.rn_leaf.rn_Dupedkey

                if rn.rn_flags & 2 == 0:
                    rt = obj.Object("rtentry", offset = rn, vm = self.addr_space)
                    yield rt

            rn = nextptr

            if rn.rn_flags & 2 != 0:
                break
            
    def calculate(self):
        common.set_plugin_members(self)

        tables_addr = self.get_profile_symbol("_rt_tables")

        ## FIXME: if we only use ents[2] why do we need to instantiate 32?
        ents = obj.Object('Array', offset = tables_addr, vm = self.addr_space, targetType = 'Pointer', count = 32)

        ipv4table = obj.Object("radix_node_head", offset = ents[2], vm = self.addr_space)

        rts = self.get_table(ipv4table)

        for rt in rts:
            yield rt

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Source IP", "16"), 
                                  ("Dest. IP", "16"), 
                                  ("Name", "^10"), 
                                  ("Sent", "^10"),
                                  ("Recv", "^10"), 
                                  ("CalTime", "^16"), 
                                  ("Time", "^20"), 
                                  ("Exp.", "^10"), 
                                  ("Delta", "")])

        for rt in data:
        
            if hasattr(rt, "base_calendartime"):
                caltime = rt.base_calendartime
                prettytime = datetime.datetime.fromtimestamp(caltime).strftime('%Y-%m-%d %H:%M:%S')
            else:
                caltime = "N/A"
                prettytime = ""
        
            if hasattr(rt, "rt_stats"):
                sent = rt.rt_stats.nstat_txpackets
                rx = rt.rt_stats.nstat_rxpackets
            else:
                sent = "N/A"
                rx = "N/A"
        
            if hasattr(rt, "rt_expire"):
                exp = rt.rt_expire
                if exp == 0:
                    delta = 0
                else:
                    delta = exp - rt.base_uptime
            else:
                exp = "N/A"
                delta = "N/A"
        
            name = "{0}{1}".format(rt.rt_ifp.if_name.dereference(), rt.rt_ifp.if_unit)
            source_ip = rt.rt_nodes[0].rn_u.rn_leaf.rn_Key.dereference_as("sockaddr").get_address()
            dest_ip = rt.rt_gateway.get_address()

            self.table_row(outfd, 
                           source_ip, 
                           dest_ip,
                           name,
                           sent, rx, 
                           caltime, 
                           prettytime, 
                           exp, 
                           delta)
                        