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

class mac_check_trap_table(common.AbstractMacCommand):
    """ Checks to see if mach trap table entries are hooked """

    def _set_vtypes(self):
        x86_10_vtypes = { 
            'mach_trap' : [ 16, {
                'mach_trap_function': [ 4, ['pointer', ['void']]]
                }]}
        x86_other_vtypes = { 
            'mach_trap' : [ 8, {
                'mach_trap_function': [ 4, ['pointer', ['void']]]
                }]}
        x64_10_vtypes = { 
            'mach_trap' : [ 40, {
                'mach_trap_function': [ 8, ['pointer', ['void']]]
                }]}
        x64_13_vtypes = { 
            'mach_trap' : [ 32, {
                'mach_trap_function': [ 8, ['pointer', ['void']]]
                }]}
        x64_other_vtypes = { 
            'mach_trap' : [ 16, {
                'mach_trap_function': [ 8, ['pointer', ['void']]]
                }]}


        arch  = self.addr_space.profile.metadata.get('memory_model', '32bit')
        major = self.addr_space.profile.metadata.get('major', 0)

        if arch == "32bit":
            if major == 10:
                vtypes = x86_10_vtypes
            else:
                vtypes = x86_other_vtypes
        else:
            if major == 10:
                vtypes = x64_10_vtypes

            elif major == 13:
                vtypes = x64_13_vtypes

            else:
                vtypes = x64_other_vtypes

        self.addr_space.profile.vtypes.update(vtypes)
        self.addr_space.profile.compile()

    def calculate(self):
        common.set_plugin_members(self)

        self._set_vtypes()

        sym_addrs = self.profile.get_all_addresses()

        table_addr = self.addr_space.profile.get_symbol("_mach_trap_table")

        ntraps = obj.Object("int", offset = self.addr_space.profile.get_symbol("_mach_trap_count"), vm = self.addr_space)
        traps = obj.Object(theType = "Array", offset = table_addr, vm = self.addr_space, count = ntraps, targetType = "mach_trap")

        for (i, trap) in enumerate(traps):
            ent_addr = trap.mach_trap_function.v()

            if not ent_addr:
                continue

            hooked = ent_addr not in sym_addrs
            
            if hooked == False:
                sym_name = self.profile.get_symbol_by_address("kernel", ent_addr)
            else:
                sym_name = "HOOKED"

            yield (table_addr, "TrapTable", i, ent_addr, sym_name, hooked)
 
    def unified_output(self, data):
        return TreeGrid([("Table Name", str),
                        ("Index", int),
                        ("Address", Address),
                        ("Symbol", str),
                        ], self.generator(data))

    def generator(self, data):
        for (_, table_name, i, call_addr, sym_name, _) in data:
            yield(0, [
                str(table_name),
                int(i),
                Address(call_addr),
                str(sym_name),
                ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Table Name", "15"), 
                                  ("Index", "6"), 
                                  ("Address", "[addrpad]"), 
                                  ("Symbol", "<50")])

        for (_, table_name, i, call_addr, sym_name, _) in data:
            self.table_row(outfd, table_name, i, call_addr, sym_name)
