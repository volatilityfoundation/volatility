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
import volatility.plugins.mac.common as common
import volatility.plugins.mac.route as route

class mac_arp(route.mac_route):
    """ prints the arp table """
    
    def calculate(self):
        common.set_plugin_members(self)

        arp_addr = self.get_profile_symbol("_llinfo_arp")
    
        ptr = obj.Object("Pointer", offset=arp_addr, vm=self.addr_space)

        ent = obj.Object("llinfo_arp", offset=ptr, vm=self.addr_space)

        while ent:
            yield ent.la_rt

            ent = ent.la_le.le_next