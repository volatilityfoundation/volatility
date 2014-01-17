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
import volatility.plugins.mac.route as route

class mac_arp(route.mac_route):
    """ Prints the arp table """
    
    def calculate(self):
        common.set_plugin_members(self)

        arp_addr = self.addr_space.profile.get_symbol("_llinfo_arp")
        ptr = obj.Object("Pointer", offset = arp_addr, vm = self.addr_space)
        ent = ptr.dereference_as("llinfo_arp") 

        while ent:
            yield ent.la_rt
            ent = ent.la_le.le_next
