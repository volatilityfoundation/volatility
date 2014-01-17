# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

import volatility.obj as obj
import volatility.plugins.mac.common as common

class mac_ifconfig(common.AbstractMacCommand):
    """ Lists network interface information for all devices """

    def calculate(self):
        common.set_plugin_members(self)    

        list_head_addr = self.addr_space.profile.get_symbol("_dlil_ifnet_head")
        list_head_ptr = obj.Object("Pointer", offset = list_head_addr, vm = self.addr_space)
        ifnet = list_head_ptr.dereference_as("ifnet")

        while ifnet:
            name = ifnet.if_name.dereference()
            unit = ifnet.if_unit
            ifaddr = ifnet.if_addrhead.tqh_first
            
            ips = []

            while ifaddr:
                ip = ifaddr.ifa_addr.get_address() 
                if ip:
                    ips.append(ip)
                ifaddr = ifaddr.ifa_link.tqe_next
     
            yield (name, unit, ips)
            ifnet = ifnet.if_link.tqe_next
 
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Interface", "10"), ("Address", "")])

        for (name, unit, ips) in data:
            if ips:
                for ip in ips:
                    self.table_row(outfd, "{0}{1}".format(name, unit), ip)
            else:
                # an interface with no IPs
                self.table_row(outfd, "{0}{1}".format(name, unit), "")
