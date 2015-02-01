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
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_check_syscalls(common.AbstractMacCommand):
    """ Checks to see if system call table entries are hooked """
 
    def __init__(self, config, *args, **kwargs):
        common.AbstractMacCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('syscall-indexes', short_option = 'i', default = None, help = 'Path to unistd_{32,64}.h from the target machine', action = 'store', type = 'str')
   
    def _parse_handler_names(self):
        index_names = {}

        lines = open(self._config.SYSCALL_INDEXES, "r").readlines()

        for line in lines:
            ents = line.split()

            if len(ents) < 6:
                continue

            if ents[3] != "{":
                continue

            name = ents[5].split("(")[0]

            try:
                index_names[int(ents[0])] = name
            except ValueError:
                pass

        return index_names

    def calculate(self):
        common.set_plugin_members(self)
        
        if self._config.SYSCALL_INDEXES:
            index_names = self._parse_handler_names()
        else:
            index_names = None

        sym_addrs = self.profile.get_all_addresses()

        table_addr = self.addr_space.profile.get_symbol("_sysent")

        nsysent = obj.Object("int", offset = self.addr_space.profile.get_symbol("_nsysent"), vm = self.addr_space)
        sysents = obj.Object(theType = "Array", offset = table_addr, vm = self.addr_space, count = nsysent, targetType = "sysent")

        for (i, sysent) in enumerate(sysents):
            ent_addr = sysent.sy_call.v()
            hooked  = ent_addr not in sym_addrs

            if index_names:
                sym_name = index_names[i]
            else:
                sym_name = self.profile.get_symbol_by_address("kernel", ent_addr)
                if not sym_name:
                    sym_name = "N/A"

            yield (table_addr, "SyscallTable", i, ent_addr, sym_name, hooked)
 
    def unified_output(self, data):
        return TreeGrid([("Table Name", str),
                         ("Index", int),
                         ("Address", Address),
                         ("Symbol", str),
                         ("Status", str),
                         ], self.generator(data))

    def generator(self, data):
        for (_, table_name, i, call_addr, sym_name, hooked) in data:
            if hooked:
                status = "HOOKED"
            else:
                status = "OK"

            yield(0, [
                str(table_name),
                int(i),
                Address(call_addr),
                str(sym_name),
                str(status),
                ])



