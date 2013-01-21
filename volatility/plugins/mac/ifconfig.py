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
import common

class mac_ifconfig(common.AbstractMacCommand):
    """ Lists network interface information for all devices """

    def calculate(self):
        common.set_plugin_members(self)    

        list_head_addr = self.get_profile_symbol("_dlil_ifnet_head")

        list_head_ptr  = obj.Object("Pointer", offset=list_head_addr, vm=self.addr_space)

        difnet = obj.Object("dlil_ifnet", offset=list_head_ptr, vm=self.addr_space)

        ifnet  = obj.Object("ifnet",      offset=list_head_ptr, vm=self.addr_space)

        while ifnet:

            name = common.get_string(ifnet.if_name, self.addr_space)

            unit = ifnet.if_unit
            
            ifaddr = ifnet.if_addrhead.tqh_first
            
            ips = []

            while ifaddr:

                ip = self.get_ip_address(ifaddr)
                
                if ip:
                    ips.append(ip)

                ifaddr = ifaddr.ifa_link.tqe_next
     
            yield (name, unit, ips)
            
            ifnet = ifnet.if_link.tqe_next        

 
    def render_text(self, outfd, data):
        for (name, unit, ips) in data:
            print "%s%d -> %s" % (name, unit, str(ips))

    def ip2str(self, ip):
        ip = ip & 0xffffffff

        a = ip & 0xff
        b = (ip >> 8) & 0xff
        c = (ip >> 16) & 0xff
        d = (ip >> 24) & 0xff

        return "%d.%d.%d.%d" % (a, b, c, d)

    def get_link_addr(self, addr):
        if addr == None:
            return None

        ret = ""

        for i in xrange(0, addr.sdl_alen):
            e  = addr.sdl_data[addr.sdl_nlen+i]

            ret = ret + "%.02x:" % ord(e.v())
    
        if ret and ret[-1] == ":":
            ret = ret[:-1]

        return ret

    def get_ipv6(self, addr):
        ret = ""

        for idx,a in enumerate(addr):
            ret = ret + "%.02x" % a.v()
 
            if idx and idx % 2 != 0:
                ret = ret + ":"

        if ret and ret[-1] == ":":
            ret = ret[:-1]

        return ret

    def get_ip_address(self, ifnet):
        addr = ifnet.ifa_addr

        family = addr.sa_family

        ip = ""

        if family == 2: # ip 4
            addr_in = obj.Object("sockaddr_in", offset=addr, vm=self.addr_space)
            ip = self.ip2str(addr_in.sin_addr.s_addr.v())

        elif family == 30:
            addr_in6 = obj.Object("sockaddr_in6", offset=addr, vm=self.addr_space)
            addr = addr_in6.sin6_addr.__u6_addr.__u6_addr8
            ip = self.get_ipv6(addr)

        elif family == 18:
            addr_dl = obj.Object("sockaddr_dl", offset=addr, vm=self.addr_space)
            ip = self.get_link_addr(addr_dl)
        
        else:
            print "family: %d" % family

        return ip
        






