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

# based on sysctl_sysctl_debug_dump_node
class mac_check_sysctl(common.AbstractMacCommand):
    """ Checks for unknown sysctl handlers """

    # define CTLFLAG_RD      0x80000000      /* Allow reads of variable */
    # define CTLFLAG_WR      0x40000000      /* Allow writes to the variable */
    # define CTLFLAG_LOCKED  0x00800000      /* node will handle locking itself */
    def _get_perms(self, sysctl):
        ret = ""

        flags = sysctl.oid_kind

        checks = [0x80000000, 0x40000000, 0x00800000]
        perms  = ["R", "W", "L"]
        
        for (i, c) in enumerate(checks):
            if c & flags:
                ret = ret + perms[i]
            else:
                ret = ret + "-"

        return ret

    def _process_sysctl_list(self, sysctl_list, i, r = 0):
        if type(sysctl_list) == obj.Pointer:
            sysctl_list = obj.Object("sysctl_oid_list", offset = sysctl_list.dereference(), vm = self.addr_space)

        sysctl = sysctl_list.slh_first
        
        # skip the head entry if new list (recursive call)
        if r:
            sysctl = sysctl = sysctl.oid_link.sle_next

        while sysctl and sysctl.is_valid():
            spaces = " " * i

            name = common.get_string(sysctl.oid_name, self.addr_space)

            if len(name) == 0:
                #sysctl = sysctl.oid_link.sle_next
                break

            num  = sysctl.oid_number

            perms = self._get_perms(sysctl)

            handler = sysctl.oid_handler


            #define CTLTYPE_NODE    1
            #define CTLTYPE_INT     2       /* name describes an integer */
            #define CTLTYPE_STRING  3       /* name describes a string */
            #define CTLTYPE_QUAD    4       /* name describes a 64-bit number */
            #define CTLTYPE_OPAQUE  5       /* name describes a structure */
            #define CTLTYPE_STRUCT  CTLTYPE_OPAQUE  /* name describes a structure */
            
            ctltype = sysctl.oid_kind & 0xf

            if sysctl.oid_arg1 == 0 or not sysctl.oid_arg1.is_valid():
                val = ""
            elif ctltype == 1:
                if handler == 0:
                    for info in self._process_sysctl_list(sysctl.oid_arg1, i + 2, r = 1):
                        yield info 
                val = "Node"
            elif ctltype == 2:
                val = sysctl.oid_arg1.dereference()
            elif ctltype == 3:
                val = common.get_string(sysctl.oid_arg1, self.addr_space)
            elif ctltype == 4:
                val = sysctl.oid_arg1.dereference()
            elif ctltype == 5:
                val = sysctl.oid_arg1.dereference()
            else:
                val = "<UNKNOWN VALUE FOR CTLTYPE %d>" % ctltype 

            yield (sysctl, spaces, name, num, perms, handler, val)

            sysctl = sysctl.oid_link.sle_next
    
    def calculate(self):
        common.set_plugin_members(self)
            
        (kernel_symbol_addresses, kmods) = common.get_kernel_addrs(self)
    
        sysctl_children_addr = self.get_profile_symbol("_sysctl__children")

        sysctl_list = obj.Object("sysctl_oid_list", offset = sysctl_children_addr, vm = self.addr_space)

        for (sysctl, spaces, name, number, perms, handler, val) in self._process_sysctl_list(sysctl_list, 0):
            if common.is_known_address(handler, kernel_symbol_addresses, kmods):
                good = 1
            else:
                good = 0

            if good == 0:
                yield (name, number, perms, handler, val)

    def render_text(self, outfd, data):
        for (name, number, perms, handler, val) in data:
            outfd.write("%s %-6d %-20s %.08x %s\n" % (name, number, perms, handler, val))



