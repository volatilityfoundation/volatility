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

import sys
import volatility.obj as obj
import volatility.plugins.mac.common as common

from lsmod import mac_lsmod as mac_lsmod

class mac_trustedbsd(mac_lsmod):
    """ Lists malicious trustedbsd policies """

    def get_members(self):
        h = self.profile.types['mac_policy_ops']
        return h.keywords["members"]

    def calculate(self):
        common.set_plugin_members(self)

        # get all the members of 'mac_policy_ops' so that we can check them (they are all function ptrs)
        ops_members = self.get_members()

        # get the symbols need to check for if rootkit or not
        (kernel_symbol_addresses, kmods) = common.get_kernel_addrs(self)

        list_addr = self.addr_space.profile.get_symbol("_mac_policy_list")
    
        plist = obj.Object("mac_policy_list", offset = list_addr, vm = self.addr_space)
        parray = obj.Object('Array', offset = plist.entries, vm = self.addr_space, targetType = 'mac_policy_list_element', count = plist.maxindex + 1)

        for ent in parray:
            # I don't know how this can happen, but the kernel makes this check all over the place
            # the policy is useful without any ops so a rootkit can't abuse this
            if ent.mpc == None:
                continue

            name = ent.mpc.mpc_name.dereference()

            ops = obj.Object("mac_policy_ops", offset = ent.mpc.mpc_ops, vm = self.addr_space)

            # walk each member of the struct
            for check in ops_members:
                ptr = ops.__getattr__(check)
               
                if ptr != 0:
                    good = common.is_known_address(ptr, kernel_symbol_addresses, kmods) 

                    yield (good, check, name, ptr)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Check", "40"), ("Name", "20"), ("Pointer", "[addrpad]")])
        for (good, check, name, ptr) in data:
            if not good:
                self.table_row(outfd, check, name, ptr)
