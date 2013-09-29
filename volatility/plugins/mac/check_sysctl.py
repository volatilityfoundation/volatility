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

    def _process_sysctl_list(self, sysctl_list, r = 0):

        if type(sysctl_list) == obj.Pointer:
            sysctl_list = sysctl_list.dereference_as("sysctl_oid_list")

        sysctl = sysctl_list.slh_first
        
        # skip the head entry if new list (recursive call)
        if r:
            sysctl = sysctl.oid_link.sle_next

        while sysctl and sysctl.is_valid():
            name = sysctl.oid_name.dereference()

            if len(name) == 0:
                break

            ctltype = sysctl.get_ctltype()

            if sysctl.oid_arg1 == 0 or not sysctl.oid_arg1.is_valid():
                val = ""
            elif ctltype == 'CTLTYPE_NODE':
                if sysctl.oid_handler == 0:
                    for info in self._process_sysctl_list(sysctl.oid_arg1, r = 1):
                        yield info 
                val = "Node"
            elif ctltype in ['CTLTYPE_INT', 'CTLTYPE_QUAD', 'CTLTYPE_OPAQUE']:
                val = sysctl.oid_arg1.dereference()
            elif ctltype == 'CTLTYPE_STRING':
                ## FIXME: can we do this without get_string?
                val = common.get_string(sysctl.oid_arg1, self.addr_space)
            else:
                val = ctltype

            yield (sysctl, name, val)

            sysctl = sysctl.oid_link.sle_next
    
    def calculate(self):
        common.set_plugin_members(self)
            
        (kernel_symbol_addresses, kmods) = common.get_kernel_addrs(self)
    
        sysctl_children_addr = self.addr_space.profile.get_symbol("_sysctl__children")

        sysctl_list = obj.Object("sysctl_oid_list", offset = sysctl_children_addr, vm = self.addr_space)

        for (sysctl, name, val) in self._process_sysctl_list(sysctl_list):
            if val == "INVALID -1":
                continue

            is_known = common.is_known_address(sysctl.oid_handler, kernel_symbol_addresses, kmods)
            
            if is_known:
                status = "OK"
            else:
                status = "UNKNOWN"

            yield (sysctl, name, val, is_known, status)

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Name", "30"), 
                                  ("Number", "8"), 
                                  ("Perms", "6"), 
                                  ("Handler", "[addrpad]"), 
                                  ("Status", "10"),
                                  ("Value", "")])

        for (sysctl, name, val, is_known, status) in data:
            self.table_row(outfd, name, 
               sysctl.oid_number, 
               sysctl.get_perms(),
               sysctl.oid_handler, 
               status, val)

