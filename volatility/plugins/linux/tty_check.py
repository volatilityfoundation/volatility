# Volatility
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
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: 504ENSICS Labs
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common


class linux_check_tty(linux_common.AbstractLinuxCommand):
    """Checks tty devices for hooks"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        tty_addr = self.addr_space.profile.get_symbol("tty_drivers")
        
        if not tty_addr:
            debug.error("Symbol tty_drivers not found in kernel")
                        
        drivers = obj.Object("list_head", offset = tty_addr, vm = self.addr_space)
        
        sym_cache = {}

        for tty in drivers.list_of_type("tty_driver", "tty_drivers"):
            name = tty.name.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)
            
            ttys = obj.Object("Array", targetType = "Pointer", vm = self.addr_space, offset = tty.ttys, count = tty.num)
            for tty_dev in ttys:
                if tty_dev == 0:
                    continue
                
                tty_dev = tty_dev.dereference_as("tty_struct")
                name = tty_dev.name
                recv_buf = tty_dev.ldisc.ops.receive_buf
                
                if recv_buf in sym_cache:
                    sym_name = sym_cache[recv_buf]
                else:
                    sym_name = self.profile.get_symbol_by_address("kernel", recv_buf)

                if not sym_name:
                    sym_name = "HOOKED"
                    hooked = 1
                else:
                    hooked = 0
                
                sym_cache[recv_buf] = sym_name
                
                yield (name, recv_buf, sym_name, hooked)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "<16"), ("Address", "[addrpad]"), ("Symbol", "<30")])
        for name, call_addr, sym_name, _hooked in data: 
            self.table_row(outfd, name, call_addr, sym_name)
