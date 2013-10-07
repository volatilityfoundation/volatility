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
@author:       Joe Sylve
@license:      GNU General Public License 2.0 or later
@contact:      joe.sylve@gmail.com
@organization: 504ENSICS Labs
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_keyboard_notifier(linux_common.AbstractLinuxCommand):
    """Parses the keyboard notifier call chain"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        knl_addr = self.addr_space.profile.get_symbol("keyboard_notifier_list")
        
        if not knl_addr:
            debug.error("Symbol keyboard_notifier_list not found in kernel")
            
        knl = obj.Object("atomic_notifier_head", offset = knl_addr, vm = self.addr_space)
        
        symbol_cache = {}
        
        for callback in linux_common.walk_internal_list("notifier_block", "next", knl.head):
            if symbol_cache.has_key(callback):
                sym_name = symbol_cache[callback]
                hooked = 0

            else:
                sym_name = self.profile.get_symbol_by_address("kernel", callback)
                if not sym_name:
                    sym_name = "HOOKED"

                hooked = 1            
        
            symbol_cache[callback] = sym_name

            yield callback.notifier_call, sym_name, hooked

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Address", "[addrpad]"), ("Symbol", "<30")])
        for call_addr, sym_name, _ in data:
            self.table_row(outfd, call_addr, sym_name)
