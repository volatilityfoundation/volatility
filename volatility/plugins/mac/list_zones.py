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

class mac_list_zones(common.AbstractMacCommand):
    """ Prints active zones """

    def calculate(self):
        common.set_plugin_members(self)

        first_zone_addr = self.addr_space.profile.get_symbol("_first_zone")

        zone_ptr = obj.Object("Pointer", offset = first_zone_addr, vm = self.addr_space)
        zone = zone_ptr.dereference_as("zone")

        while zone:
            yield zone
            zone = zone.next_zone       
 
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "30"), ("Active Count", ">10"), ("Free Count", ">10"), ("Element Size", ">10")])
        for zone in data:
            name = zone.zone_name.dereference().replace(" ", ".")
            self.table_row(outfd, name, zone.count, zone.sum_count - zone.count, zone.elem_size)

