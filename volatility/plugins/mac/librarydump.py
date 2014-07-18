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
import volatility.plugins.mac.procdump as mac_procdump

class mac_librarydump(mac_tasks.mac_tasks):
    """ Dumps the executable of a process """

    def __init__(self, config, *args, **kwargs):         
        mac_tasks.mac_tasks.__init__(self, config, *args, **kwargs)         
        self._config.add_option('BASE', short_option = 'b', default = None, help = 'Dump driver with BASE address (in hex)', action = 'store', type = 'int')
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

    def _write_file(self, proc, exe_address, path):
        exe_contents = mac_procdump.mac_procdump(self._config).get_executable_contents(proc, exe_address, path)
    
        file_name = "task.{0}.{1:#x}.dmp".format(proc.p_pid, exe_address)
        file_path = os.path.join(self._config.DUMP_DIR, file_name)

        outfile = open(file_path, "wb+")
        outfile.write(exe_contents)            
        outfile.close()

        return file_path

    def render_text(self, outfd, data):
        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")
 
        self.table_header(outfd, [("Task", "25"), 
                                  ("Pid", "6"),
                                  ("Address", "[addrpad]"),
                                  ("Path", "")])
       
        for proc in data:
            addresses = []

            if self._config.BASE:
                addresses = [self._config.BASE]
            else:
                for map in proc.get_dyld_maps():        
                    addresses.append((map.imageFilePath, map.imageLoadAddress))
 
            for (path, address) in addresses:
                file_path = self._write_file(proc, address, path)
                self.table_row(outfd, proc.p_comm, proc.p_pid, address, file_path)


