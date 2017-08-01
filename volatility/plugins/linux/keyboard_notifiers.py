# Volatility
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
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: 504ENSICS Labs
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_keyboard_notifiers(linux_common.AbstractLinuxCommand):
    """Parses the keyboard notifier call chain"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        knl_addr = self.addr_space.profile.get_symbol("keyboard_notifier_list")
        
        if not knl_addr:
            debug.error("Symbol keyboard_notifier_list not found in kernel")
            
        knl = obj.Object("atomic_notifier_head", offset = knl_addr, vm = self.addr_space)
        
        symbol_cache = {}
        
        for call_back in linux_common.walk_internal_list("notifier_block", "next", knl.head):
            call_addr = call_back.notifier_call
            
            if symbol_cache.has_key(call_addr):
                sym_name = symbol_cache[call_addr]
                hooked = 0

            else:
                sym_name = self.profile.get_symbol_by_address("kernel", call_addr)
                if not sym_name:
                    sym_name = "HOOKED"
                    
                hooked = 1            
        
            symbol_cache[call_addr] = sym_name

            yield call_addr, sym_name, hooked

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Address", "[addrpad]"), ("Symbol", "<30")])
        for call_addr, sym_name, _ in data:
            self.table_row(outfd, call_addr, sym_name)
