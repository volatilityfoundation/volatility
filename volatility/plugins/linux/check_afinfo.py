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

import os

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsof as linux_lsof
import volatility.plugins.linux.lsmod as linux_lsmod

class linux_check_afinfo(linux_common.AbstractLinuxCommand):
    """Verifies the operation function pointers of network protocols"""

    def check_members(self, var_ops, var_name, members, modules):

        for (hooked_member, hook_address) in linux_common.verify_ops(self, var_ops, members, modules):
            yield (hooked_member, hook_address)

    def check_afinfo(self, var_name, var, op_members, seq_members, modules):

        for (hooked_member, hook_address) in self.check_members(var.seq_fops, var_name, op_members,  modules):
            yield (var_name, hooked_member, hook_address)

        for (hooked_member, hook_address) in self.check_members(var.seq_ops, var_name, seq_members, modules):
            yield (var_name, hooked_member, hook_address) 
            
    def calculate(self):
        self.known_addrs = {}
        
        modules  = linux_lsmod.linux_lsmod(self._config).get_modules()
        op_members  = self.profile.types['file_operations'].keywords["members"].keys()
        seq_members = self.profile.types['seq_operations'].keywords["members"].keys()       

        tcp = ("tcp_seq_afinfo", ["tcp6_seq_afinfo", "tcp4_seq_afinfo"])
        udp = ("udp_seq_afinfo", ["udplite6_seq_afinfo", "udp6_seq_afinfo", "udplite4_seq_afinfo", "udp4_seq_afinfo"])
        protocols = [tcp, udp]

        for proto in protocols:
            
            struct_type = proto[0]

            for global_var_name in proto[1]:
                
                global_var_addr = self.get_profile_symbol(global_var_name)

                if not global_var_addr:
                    continue

                global_var = obj.Object(struct_type, offset=global_var_addr, vm=self.addr_space)

                for (name, member, address) in self.check_afinfo(global_var_name, global_var, op_members, seq_members, modules):
                    yield (name, member, address)
        
    def render_text(self, outfd, data):

        self.table_header(outfd, [("What", "42"), 
                                  ("Member", "30"), 
                                  ("Address", "[addr]")])
                                  
        for (what, member, address) in data:
            self.table_row(outfd, what, member, address)


