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

import sys
import volatility.obj as obj
import volatility.plugins.mac.common as common

from lsmod import mac_lsmod as mac_lsmod

class mac_trustedbsd(mac_lsmod):
    """ Lists malicious trustedbsd policies """

    def get_members(self):
        h = self.profile.types['mac_policy_ops']
        h = h.keywords["members"]

        return h

    def calculate(self):
        common.set_plugin_members(self)

        # get all the members of 'mac_policy_ops' so that we can check them (they are all function ptrs)
        ops_members = self.get_members()

        # get the symbols need to check for if rootkit or not
        (kernel_symbol_addresses, kmods) = common.get_kernel_addrs(self)

        list_addr = self.get_profile_symbol("_mac_policy_list")
    
        plist = obj.Object("mac_policy_list", offset=list_addr, vm=self.addr_space)

        parray = obj.Object(theType = 'Array', offset = plist.entries, vm = self.addr_space, targetType = 'mac_policy_list_element', count = plist.maxindex+1)

        for (i, ent) in enumerate(parray):
            # I don't know how this can happen, but the kernel makes this check all over the place
            # the policy is useful without any ops so a rootkit can't abuse this
            if ent.mpc == None:
                continue

            name = common.get_string(ent.mpc.mpc_name, self.addr_space)

            ops = obj.Object("mac_policy_ops", offset=ent.mpc.mpc_ops, vm=self.addr_space)

            # walk each member of the struct
            for check in ops_members:
                ptr = ops.__getattr__(check)
               
                if ptr != 0:
                    # make the last parameter 1 to see the names of known modules that load policies
                    good = common.is_known_address(ptr, kernel_symbol_addresses, kmods, 0) 

                    yield (good, check, name, ptr)

    def render_text(self, outfd, data):
        for (good, check, name, ptr) in data:
            if good == 0:
                print "unknown hook for %s in policy %s at %x" % (check, name, ptr)
            #else:
            #    print "known hook for %s in policy %s at %x" % (check, name, ptr)

