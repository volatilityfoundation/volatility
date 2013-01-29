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
                    rt = obj.Object("rtentry", offset=rn, vm=self.addr_space)
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

    def get_ip(self, addr):
    
        dst = obj.Object("sockaddr", offset = addr, vm = self.addr_space)
    
        if dst.sa_family == 2: # AF_INET
        
            saddr = obj.Object("sockaddr_in", offset = addr, vm = self.addr_space)
        
            s = obj.Object(theType = 'Array', offset = saddr.sin_addr.v(), vm = self.addr_space, targetType = 'unsigned char', count = 4)
    
            ip = "{0}.{1}.{2}.{3}".format(s[0], s[1], s[2], s[3])
    
        elif dst.sa_family == 18:  # AF_LINK
    
            s = obj.Object("sockaddr_dl", offset = addr, vm = self.addr_space)
    
            if [s.sdl_nlen, s.sdl_alen, s.sdl_slen] == [0,0,0]:
                ip = "link{0}".format(s.sdl_index)
            else:
                ip = ":".join(["%02x" % ord(x.v()) for x in s.sdl_data[s.sdl_nlen : s.sdl_nlen + s.sdl_alen]])  
                
        else:
            ip = "unknown"
    
        return ip

    def render_text(self, outfd, data):

        for rt in data:
            src_ip = self.get_ip(rt.rt_nodes[0].rn_u.rn_leaf.rn_Key)
            dst_ip = self.get_ip(rt.rt_gateway)
        
            name = common.get_string(rt.rt_ifp.if_name, self.addr_space)
        
            unit = rt.rt_ifp.if_unit
        
            if hasattr(rt, "base_calendartime"):
                caltime = rt.base_calendartime
                prettytime = datetime.datetime.fromtimestamp(caltime).strftime('%Y-%m-%d %H:%M:%S')
            else:
                caltime = -1
                prettytime = ""
        
            if hasattr(rt, "rt_stats"):
                sent = rt.rt_stats.nstat_txpackets
                rx = rt.rt_stats.nstat_rxpackets
            else:
                sent = -1
                rx = -1
        
            if hasattr(rt, "rt_expire"):
                exp = rt.rt_expire
                if exp == 0:
                    delta = 0
                else:
                    delta = exp - rt.base_uptime
            else:
                exp = -1
                delta = -1
        
            outfd.write("{0} : {1} - {2}{3} - {4} - {5} | {6} {7} | {8} {9}\n".format(src_ip, dst_ip, name, unit, sent, rx, caltime, prettytime, exp, delta))


