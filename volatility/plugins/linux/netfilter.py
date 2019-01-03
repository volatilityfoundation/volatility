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
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod as linux_lsmod
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_netfilter(linux_common.AbstractLinuxCommand):
    """Lists Netfilter hooks"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        hook_names = ["PRE_ROUTING", "LOCAL_IN", "FORWARD", "LOCAL_OUT", "POST_ROUTING"]

        proto_names = ["UNSPEC", "INET", "IPV4", "ARP", "", "NETDEV", "", "BRIDGE", "", "", "IPV6" , "", "DECNET"]

        nf_hooks_addr = self.addr_space.profile.get_symbol("nf_hooks")

        if nf_hooks_addr == None:
            debug.error("Unable to analyze NetFilter. It is either disabled or compiled as a module.")

        modules  = linux_lsmod.linux_lsmod(self._config).get_modules()
         
        list_head_size = self.addr_space.profile.get_obj_size("list_head")
        
        for proto_idx, proto_name in enumerate(proto_names):
            arr = nf_hooks_addr + (proto_idx * (list_head_size * 8))
           
            for hook_idx, hook_name in enumerate(hook_names):
                list_head = obj.Object("list_head", offset = arr + (hook_idx * list_head_size), vm = self.addr_space)
        
                for hook_ops in list_head.list_of_type("nf_hook_ops", "list"):
                    found, module = self.is_known_address_name(hook_ops.hook.v(), modules) or ""
                    hooked = "False" if found else "True"

                    yield proto_name, hook_name, hook_ops.hook.v(), hooked, module

    def unified_output(self, data):
        return TreeGrid([("Proto", str),
                       ("Hook", str),
                       ("Handler", Address),
                       ("IsHooked", str),
                       ("Module", str)],
                        self.generator(data))

    def generator(self, data):
        for proto_name, hook_name, hook_addr, hooked, module in data:
            yield (0, [str(proto_name), str(hook_name), Address(hook_addr), str(hooked), str(module)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Proto", "10"), ("Hook", "16"), ("Handler", "[addrpad]"), ("Is Hooked", "5"), ("Module", "30")])

        for proto_name, hook_name, hook_addr, hooked, module in data:
            self.table_row(outfd, proto_name, hook_name, hook_addr, hooked, module)

