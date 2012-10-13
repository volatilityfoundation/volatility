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

class mac_arp(mac_common.AbstractMacCommand):
    """ prints the arp table """
    
    def calculate(self):

        arp_addr = self.smap["_llinfo_arp"]
    
        ptr = obj.Object("Pointer", offset=arp_addr, vm=self.addr_space)

        ent = obj.Object("llinfo_arp", offset=ptr, vm=self.addr_space)

        while ent:

            yield ent.la_rt

            ent = ent.la_le.le_next

    def render_text(self, outfd, data):
        for rt in data:
            mac_common.print_rt(self, rt) 
