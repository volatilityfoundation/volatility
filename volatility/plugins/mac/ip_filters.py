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
import volatility.plugins.mac.lsmod as lsmod
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address


class mac_ip_filters(lsmod.mac_lsmod):
    """ Reports any hooked IP filters """

    def check_filter(self, context, fname, ptr, kernel_symbol_addresses, kmods):
        if ptr == None:
            return

        # change the last paramter to 1 to get messages about which good modules hooks were found in
        good = common.is_known_address_name(ptr, kernel_symbol_addresses, kmods) 

        return (good, context, fname, ptr)

    def calculate(self):
        common.set_plugin_members(self)
        
        # get the symbols need to check for if rootkit or not
        (kernel_symbol_addresses, kmods) = common.get_kernel_addrs(self)

        list_addrs = [self.addr_space.profile.get_symbol("_ipv4_filters"), self.addr_space.profile.get_symbol("_ipv6_filters")]
    
        for list_addr in list_addrs:
            plist = obj.Object("ipfilter_list", offset = list_addr, vm = self.addr_space)

            # type 'ipfilter'
            cur = plist.tqh_first

            while cur:
                filter = cur.ipf_filter
                name = filter.name.dereference()
                   
                yield self.check_filter("INPUT", name, filter.ipf_input, kernel_symbol_addresses, kmods)
                yield self.check_filter("OUTPUT", name, filter.ipf_output, kernel_symbol_addresses, kmods)
                yield self.check_filter("DETACH", name, filter.ipf_detach, kernel_symbol_addresses, kmods)
           
                cur = cur.ipf_link.tqe_next

    def unified_output(self, data):
        return TreeGrid([("Context", str),
                        ("Filter", str),
                        ("Pointer", Address),
                        ("Status", str)
                        ], self.generator(data))

    def generator(self, data):
        for (good, context, fname, ptr) in data:
            status = "OK"
            if good == 0:
                status = "UNKNOWN"
            yield (0,[
                str(context),
                str(fname),
                Address(ptr),
                str(status),
                ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Context", "10"), 
                                  ("Filter", "16"), 
                                  ("Pointer", "[addrpad]"), 
                                  ("Status", "")])

        for (good, context, fname, ptr) in data:
            status = "OK"
            if good == 0:
                status = "UNKNOWN"
            self.table_row(outfd, context, fname, ptr, status)
