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
import mac_common
import sys
from mac_lsmod import mac_lsmod as mac_lsmod

class mac_ip_filters(mac_lsmod):

    def check_filter(self, context, fname, ptr, kernel_symbol_addresses, kmods):

        if ptr == None:
            return

        # change the last paramter to 1 to get messages about which good modules hooks were found in
        good = mac_common.is_known_address(ptr, kernel_symbol_addresses, kmods, 0) 

        if good == 0:
            print "unknown %s hook %s at %x" % (context, fname, ptr)
        #else:
        #    print "known %s hook %s at %x" % (context, fname, ptr)

    def calculate(self):

        # get the symbols need to check for if rootkit or not
        (kernel_symbol_addresses, kmods) = mac_common.get_kernel_addrs(self)

        list_addr = self.smap["_ipv4_filters"]
    
        plist = obj.Object("ipfilter_list", offset=list_addr, vm=self.addr_space)

        # type 'ipfilter'
        cur = plist.tqh_first

        while cur:
            
            filter = cur.ipf_filter
            
            name = mac_common.get_string(filter.name, self.addr_space)
   
            self.check_filter("INPUT",  name, filter.ipf_input,  kernel_symbol_addresses, kmods)
            self.check_filter("OUTPUT", name, filter.ipf_output, kernel_symbol_addresses, kmods)
            self.check_filter("DETACH", name, filter.ipf_detach, kernel_symbol_addresses, kmods)
       
            cur = cur.ipf_link.tqe_next

        yield []

    def render_text(self, outfd, data):
        for blah in data:
            pass
