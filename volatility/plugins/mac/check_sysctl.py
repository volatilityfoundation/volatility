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
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

# based on sysctl_sysctl_debug_dump_node
class mac_check_sysctl(common.AbstractMacCommand):
    """ Checks for unknown sysctl handlers """
    
    # returns the value for known, hardcoded-sysctls, otherwise ""
    def _parse_global_variable_sysctls(self, name):
        known_sysctls = {
            "hostname"      : "_hostname",
            "nisdomainname" : "_domainname",
            }

        if name in known_sysctls:
            var_name = known_sysctls[name]

            var_addr = self.addr_space.profile.get_symbol(var_name)

            var_str = common.get_string(var_addr, self.addr_space)

        else:
            var_str = ""

        return var_str

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

            name = str(name)

            ctltype = sysctl.get_ctltype()

            if sysctl.oid_arg1 == 0 or not sysctl.oid_arg1.is_valid():
                val = self._parse_global_variable_sysctls(name)
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

            (is_known, module_name) = common.is_known_address_name(sysctl.oid_handler.v(), kernel_symbol_addresses, kmods)
            
            if is_known:
                status = "OK"
            else:
                status = "UNKNOWN"

            yield (sysctl, name, val, is_known, module_name, status)

    def unified_output(self, data):

        return TreeGrid([("Name", str),
                        ("Number", int),
                        ("Perms", str),
                        ("Handler", Address),
                        ("Value", str),
                        ("Module", str),
                        ("Status", str),
                        ], self.generator(data))

    def generator(self, data):
        for (sysctl, name, val, is_known, module_name, status) in data:
            yield(0, [
               str(name),
               int(sysctl.oid_number),
               str(sysctl.get_perms()),
               Address(sysctl.oid_handler),
               str(val),
               str(module_name),
               str(status),
               ])

