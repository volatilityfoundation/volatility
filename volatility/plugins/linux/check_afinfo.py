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

import os
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod as linux_lsmod

class linux_check_afinfo(linux_common.AbstractLinuxCommand):
    """Verifies the operation function pointers of network protocols"""

    def check_members(self, var_ops, var_name, members, modules):

        for (hooked_member, hook_address) in self.verify_ops(var_ops, members, modules):
            yield (hooked_member, hook_address)

    def check_afinfo(self, var_name, var, op_members, seq_members, modules):

        for (hooked_member, hook_address) in self.check_members(var.seq_fops, var_name, op_members,  modules):
            yield (var_name, hooked_member, hook_address)

        # newer kernels
        if hasattr(var, "seq_ops"):
            for (hooked_member, hook_address) in self.check_members(var.seq_ops, var_name, seq_members, modules):
                yield (var_name, hooked_member, hook_address) 
                
        elif not self.is_known_address(var.seq_show, modules):
            yield (var_name, "show", var.seq_show)

    def calculate(self):
        linux_common.set_plugin_members(self)
        
        modules  = linux_lsmod.linux_lsmod(self._config).get_modules()
        op_members  = self.profile.types['file_operations'].keywords["members"].keys()
        seq_members = self.profile.types['seq_operations'].keywords["members"].keys()       

        tcp = ("tcp_seq_afinfo", ["tcp6_seq_afinfo", "tcp4_seq_afinfo"])
        udp = ("udp_seq_afinfo", ["udplite6_seq_afinfo", "udp6_seq_afinfo", "udplite4_seq_afinfo", "udp4_seq_afinfo"])
        protocols = [tcp, udp]

        for proto in protocols:
            
            struct_type = proto[0]

            for global_var_name in proto[1]:
                
                global_var_addr = self.addr_space.profile.get_symbol(global_var_name)

                if not global_var_addr:
                    continue

                global_var = obj.Object(struct_type, offset = global_var_addr, vm = self.addr_space)

                for (name, member, address) in self.check_afinfo(global_var_name, global_var, op_members, seq_members, modules):
                    yield (name, member, address)
        
    def render_text(self, outfd, data):

        self.table_header(outfd, [("Symbol Name", "42"), 
                                  ("Member", "30"), 
                                  ("Address", "[addrpad]")])
                                  
        for (what, member, address) in data:
            self.table_row(outfd, what, member, address)


