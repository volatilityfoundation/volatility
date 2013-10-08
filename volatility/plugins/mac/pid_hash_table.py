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

import volatility.plugins.mac.pslist as pslist
import volatility.obj as obj
import volatility.plugins.mac.common as common

class mac_pid_hash_table(pslist.mac_pslist):
    """ Walks the pid hash table """

    def calculate(self):
        common.set_plugin_members(self)
            
        pidhash_addr = self.addr_space.profile.get_symbol("_pidhash") 
        pidhash = obj.Object("unsigned long", offset = pidhash_addr, vm = self.addr_space)

        pidhashtbl_addr = self.addr_space.profile.get_symbol("_pidhashtbl")
        pidhashtbl_ptr = obj.Object("Pointer", offset = pidhashtbl_addr, vm = self.addr_space)
        pidhash_array = obj.Object("Array", targetType = "pidhashhead", count = pidhash + 1, vm = self.addr_space, offset = pidhashtbl_ptr)
    
        for plist in pidhash_array:
            p = plist.lh_first
    
            while p:
                yield p                
                p = p.p_hash.le_next
