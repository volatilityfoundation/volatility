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

### based entirely on keychaindump from volafox

import volatility.obj as obj
import volatility.plugins.mac.pstasks as pstasks 
import volatility.plugins.mac.common as common

class mac_keychaindump(pstasks.mac_tasks):
    """ Recovers possbile keychain keys. Use chainbreaker to open related keychain files """

    def calculate(self):
        common.set_plugin_members(self)

        procs = pstasks.mac_tasks.calculate(self)

        if self.addr_space.profile.metadata.get('memory_model', '32bit') == "32bit":
            ptr_sz = 4
        else:
            ptr_sz = 8

        for proc in procs:
            if str(proc.p_comm) != "securityd":
                continue

            proc_as = proc.get_process_address_space()

            for map in proc.get_proc_maps():
                if not (map.start > 0x00007f0000000000 and map.end < 0x00007fff00000000 and map.end - map.start == 0x100000):
                    continue

                for address in range(map.start, map.end, ptr_sz):
                    signature = obj.Object("unsigned int", offset = address, vm = proc_as)
            
                    if not signature or signature != 0x18:
                        continue

                    key_buf_ptr = obj.Object("unsigned long", offset = address + ptr_sz, vm = proc_as)

                    if map.start <= key_buf_ptr < map.end:
                        yield proc_as, key_buf_ptr
                                                    
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Key", "")])

        for (proc_as, key_buf_ptr) in data:
            key_buf = proc_as.read(key_buf_ptr, 24)
            if not key_buf:
                continue

            key = "".join('%02X'%ord(k) for k in key_buf)
            self.table_row(outfd, key)


