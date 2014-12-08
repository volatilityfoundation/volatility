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
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.plthook as linux_plthook
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

   
class linux_apihooks(linux_pslist.linux_pslist):
    """Checks for userland apihooks"""

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                       ("Name", str),
                       ("HookVMA", str),
                       ("HookSymbol", str),
                       ("HookedAddress", Address),
                       ("HookType", str),
                       ("HookAddress", Address),
                       ("HookLibrary", str)],
                        self.generator(data))

    def generator(self, data):
        linux_common.set_plugin_members(self)

        try:
            import distorm3
        except ImportError:
            debug.error("this plugin requres the distorm library to operate.")
         
        for task in data:
            for hook_desc, sym_name, addr, hook_type, hook_addr, hookfuncdesc in task.apihook_info():
                yield (0, [int(task.pid), str(task.comm), str(hook_desc), str(sym_name),
                        Address(addr), str(hook_type), Address(hook_addr), str(hookfuncdesc)])


    def render_text(self, outfd, data):
        self.table_header(outfd, [
              ("Pid", "7"),
              ("Name", "16"),
              ("Hook VMA", "40"),
              ("Hook Symbol", "24"),
              ("Hooked Address", "[addrpad]"),
              ("Type", "5"),
              ("Hook Address", "[addrpad]"),
              ("Hook Library", ""),
              ])

        linux_common.set_plugin_members(self)

        try:
            import distorm3
        except ImportError:
            debug.error("this plugin requres the distorm library to operate.")

        for task in data:
            for hook_desc, sym_name, addr, hook_type, hook_addr, hookfuncdesc in task.apihook_info():
                self.table_row(outfd, task.pid, task.comm, hook_desc, sym_name, addr, hook_type, hook_addr, hookfuncdesc)

