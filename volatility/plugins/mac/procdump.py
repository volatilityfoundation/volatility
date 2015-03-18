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

import os
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.mac.pstasks as mac_tasks
import volatility.plugins.mac.common  as mac_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_procdump(mac_tasks.mac_tasks):
    """ Dumps the executable of a process """

    def __init__(self, config, *args, **kwargs):         
        mac_tasks.mac_tasks.__init__(self, config, *args, **kwargs)         
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

    def unified_output(self, data):
        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")
 
        return TreeGrid([("Task", str),
                        ("Pid", int),
                        ("Address", Address),
                        ("Path", str),
                        ], self.generator(data))

    def generator(self, data):
        for proc in data:
            exe_address = proc.text_start()

            if exe_address:
                file_path = mac_common.write_macho_file(self._config.DUMP_DIR, proc, exe_address)
                yield (0, [
                    str(proc.p_comm),
                    int(proc.p_pid),
                    Address(exe_address),
                    str(file_path),
                    ])

    def render_text(self, outfd, data):
        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")
 
        self.table_header(outfd, [("Task", "25"), 
                                  ("Pid", "6"),
                                  ("Address", "[addrpad]"),
                                  ("Path", "")])
       
        for proc in data:
            exe_address = proc.text_start()
            if exe_address:
                file_path = mac_common.write_macho_file(self._config.DUMP_DIR, proc, exe_address)
                self.table_row(outfd, proc.p_comm, proc.p_pid, exe_address, file_path)

