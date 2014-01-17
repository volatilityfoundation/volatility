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
import common

class mac_check_syscalls(common.AbstractMacCommand):
    """ Checks to see if system call table entries are hooked """

    def calculate(self):
        common.set_plugin_members(self)

        sym_addrs = self.profile.get_all_addresses()

        table_addr = self.addr_space.profile.get_symbol("_sysent")

        nsysent = obj.Object("int", offset = self.addr_space.profile.get_symbol("_nsysent"), vm = self.addr_space)
        sysents = obj.Object(theType = "Array", offset = table_addr, vm = self.addr_space, count = nsysent, targetType = "sysent")

        for (i, sysent) in enumerate(sysents):
            ent_addr = sysent.sy_call.v()
            hooked  = ent_addr not in sym_addrs

            if hooked == False:
                sym_name = self.profile.get_symbol_by_address("kernel", ent_addr)
            else:
                sym_name = "HOOKED"

            yield (table_addr, "SyscallTable", i, ent_addr, hooked, sym_name)
 
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Table Name", "15"), ("Index", "6"), ("Address", "[addrpad]"), ("Symbol", "<30")])
        for (_, table_name, i, call_addr, hooked, sym_name) in data:
            self.table_row(outfd, table_name, i, call_addr, sym_name)



