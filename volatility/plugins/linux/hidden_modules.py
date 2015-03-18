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
import re

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod  as linux_lsmod
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_hidden_modules(linux_common.AbstractLinuxCommand):
    """Carves memory to find hidden kernel modules"""

    def walk_modules_address_space(self, addr_space):
        list_mods = [x[0].obj_offset for x in linux_lsmod.linux_lsmod(self._config).calculate()]

        min_addr_sym = obj.Object("unsigned long", offset = addr_space.profile.get_symbol("module_addr_min"), vm = addr_space)
        max_addr_sym = obj.Object("unsigned long", offset = addr_space.profile.get_symbol("module_addr_max"), vm = addr_space)

        min_addr = min_addr_sym & ~0xfff
        max_addr = (max_addr_sym & ~0xfff) + 0x1000
        
        scan_buf = ""
        llen = max_addr - min_addr
        
        allfs = "\xff" * 4096 
        
        memory_model = self.addr_space.profile.metadata.get('memory_model', '32bit')
        if memory_model == '32bit':
            minus_size = 4
        else:
            minus_size = 8
 
        check_bufs = []
        replace_bufs = []
        
        check_nums = [3000, 2800, 2700, 2500, 2300, 2100, 2000, 1500, 1300, 1200, 1024, 512, 256, 128, 96, 64, 48, 32, 24, 16, 12, 9]
        if minus_size == 4:
            check_nums = check_nums + [8, 6, 5]

        for num in check_nums:
            check_bufs.append("\x00" * num)        
            replace_bufs.append(("\xff" * (num-minus_size)) + "\x00" * minus_size)

        for page in range(min_addr, max_addr, 4096):
            to_append = allfs

            tmp = addr_space.read(page, 4096)
            if tmp:
                non_zero = False
                for t in tmp:
                    if t != "\x00":
                        non_zero = True
                        break

                if non_zero:
                    for i in range(len(check_nums)):
                        tmp = tmp.replace(check_bufs[i], replace_bufs[i])
                    to_append = tmp

            scan_buf = scan_buf + to_append

        for cur_addr in re.finditer("(?=(\x00\x00\x00\x00|\x01\x00\x00\x00|\x02\x00\x00\x00))", scan_buf):
            mod_addr = min_addr + cur_addr.start()

            if mod_addr in list_mods:
                continue

            m = obj.Object("module", offset = mod_addr, vm = addr_space)

            if m.is_valid():
                yield m

    def calculate(self):
        linux_common.set_plugin_members(self)

        for mod in self.walk_modules_address_space(self.addr_space):
            yield mod

    def unified_output(self, data):
        return TreeGrid([("Offset(V)", Address),
                       ("Name", str)],
                        self.generator(data))

    def generator(self, data):
        for module in data:
            yield (0, [Address(module.obj_offset), str(module.name)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"), ("Name", "")])

        for module in data:
            self.table_row(outfd, module.obj_offset, str(module.name))

