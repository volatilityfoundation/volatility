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

import volatility.plugins.mac.pslist as pslist
import volatility.obj as obj
import volatility.plugins.mac.common as common

class mac_pgrp_hash_table(pslist.mac_pslist):
    """ Walks the process group hash table """

    def calculate(self):
        common.set_plugin_members(self)
            
        pgrphash_addr = self.addr_space.profile.get_symbol("_pgrphash") 
        pgrphash = obj.Object("unsigned long", offset = pgrphash_addr, vm = self.addr_space)

        pgrphashtbl_addr = self.addr_space.profile.get_symbol("_pgrphashtbl")
        pgrphashtbl_ptr = obj.Object("Pointer", offset = pgrphashtbl_addr, vm = self.addr_space)
        pgrphash_array = obj.Object("Array", targetType = "pgrphashhead", count = pgrphash + 1, vm = self.addr_space, offset = pgrphashtbl_ptr)
    
        for plist in pgrphash_array:
            pgrp = plist.lh_first
    
            while pgrp:
                p = pgrp.pg_members.lh_first

                while p:
                    yield p
                    p = p.p_pglist.le_next 
    
                pgrp = pgrp.pg_hash.le_next
