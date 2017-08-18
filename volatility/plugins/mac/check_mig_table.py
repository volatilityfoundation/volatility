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
import volatility.debug as debug
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_check_mig_table(common.AbstractMacCommand):
    """ Lists entires in the kernel's MIG table """

    def calculate(self):
        common.set_plugin_members(self)
       
        n = 1024
        mig_buckets_addr = self.addr_space.profile.get_symbol("_mig_buckets")

        if self.addr_space.profile.has_type("mig_hash_t"):
            ele_size = self.addr_space.profile.get_obj_size("mig_hash_t")
            
            ele_type = "mig_hash_t"
       
        else:
            # we can't use an array as the size of mig_hash_entry
            # depends on if MAC_COUNTERS is set, which changes between kernels
            # mig_table_max_displ is declared directly after mig_buckets
            # which allows us to calculate the size of each entry dynamically
            di_addr  = self.addr_space.profile.get_symbol("_mig_table_max_displ")
            ele_size = (di_addr - mig_buckets_addr) / n
            
            ele_type = "mig_hash_entry"

        for i in range(n):
            entry = obj.Object(ele_type, offset = mig_buckets_addr + (i * ele_size), vm = self.addr_space)

            if entry.routine == 0:
                continue

            rname = self.addr_space.profile.get_symbol_by_address("kernel", entry.routine)
            if not rname or rname == "":
                rname = "HOOKED"

            yield (entry.num, rname, entry.routine)

    def unified_output(self, data):
        return TreeGrid([("Index", int),
                          ("Routine Name", str),
                          ("Routine Handler", Address),
                          ], self.generator(data))

    def generator(self, data):
        for (num, name, routine) in data:
            yield(0, [
                int(num),
                str(name),
                Address(routine),
                ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Index", "8"),
                          ("Routine Name", "100"),
                          ("Routine Handler", "[addrpad]")])

        for (num, name, routine) in data:
            self.table_row(outfd, num, name, routine) 

