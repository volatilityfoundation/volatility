# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
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
    
            # sum_count was introduced in 10.8.x
            # do not want to overlay as 0 b/c we mess up subtraction
            if hasattr(zone, "sum_count"):
                sum_count = zone.sum_count - zone.count
            else:
                sum_count = "N/A"

            self.table_row(outfd, name, zone.count, sum_count, zone.elem_size)

