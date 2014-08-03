# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod  as linux_lsmod

class linux_hidden_modules(linux_common.AbstractLinuxCommand):
    """Carves memory to find hidden kernel modules"""

    def walk_modules_address_space(self, addr_space):
        mods = [x[0].obj_offset for x in linux_lsmod.linux_lsmod(self._config).calculate()]

        min_addr = obj.Object("unsigned long", offset = addr_space.profile.get_symbol("module_addr_min"), vm = addr_space)
        max_addr = obj.Object("unsigned long", offset = addr_space.profile.get_symbol("module_addr_max"), vm = addr_space)

        for cur_addr in range(min_addr, max_addr, 8):
            m = obj.Object("module", offset = cur_addr, vm = addr_space)

            if m.state.v() not in [0, 1, 2]:
                continue
 
            if m.core_size < 4096 or m.core_size > 1000000:
                continue

            if m.core_text_size < 4096 or m.core_text_size > 1000000:
                continue
                     
            s = self.addr_space.read(m.name.obj_offset, 64)
            if not s:
                continue

            idx = s.find("\x00")

            if idx < 1:
                continue
    
            name = s[:idx]
            for n in name:
                if not (32 < ord(n) < 127):
                    continue

            if not m.module_core.is_valid():
                continue

            if m.obj_offset not in mods:
                yield m

    def calculate(self):
        linux_common.set_plugin_members(self)

        for mod in self.walk_modules_address_space(self.addr_space):
            yield mod

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"), ("Name", "")])

        for module in data:
            self.table_row(outfd, module.obj_offset, str(module.name))



