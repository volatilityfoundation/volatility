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
import volatility.plugins.mac.proc_maps as proc_maps

class mac_dump_maps(proc_maps.mac_proc_maps):
    """ Dumps memory ranges of processes """

    def __init__(self, config, *args, **kwargs):         
        proc_maps.mac_proc_maps.__init__(self, config, *args, **kwargs)         
        self._config.add_option('MAP_ADDRESS', short_option = 's', default = None, help = 'Filter by starting address of map', action = 'store', type = 'long')
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')
        self._config.add_option('MAX-SIZE', short_option = 'M', default = 0x40000000, action = 'store', type = 'long', help = 'Set the maximum size (default is 1GB)') 
 
    def render_text(self, outfd, data):
        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")
 
        self.table_header(outfd, [("Task", "10"), 
                                  ("VM Start", "[addrpad]"), 
                                  ("VM End", "[addrpad]"), 
                                  ("Length", "[addr]"), 
                                  ("Path", "")])
       
        if self._config.MAP_ADDRESS:
            map_address = self._config.MAP_ADDRESS
        else:
            map_address = None

        for proc, map in data: 
            if map_address and map_address != map.links.start:
                continue

            if map.links.end - map.links.start > self._config.MAX_SIZE:
                debug.warning("Skipping max size entry {0:#x} - {1:#x}".format(map.links.start, map.links.end))
                continue

            file_name = "task.{0}.{1:#x}.dmp".format(proc.p_pid, map.links.start)
            file_path = os.path.join(self._config.DUMP_DIR, file_name)

            outfile = open(file_path, "wb+")
            
            map_address = self._config.MAP_ADDRESS

            size = 0
            for page in self._read_addr_range(proc, map.links.start, map.links.end):
                size += len(page)
                outfile.write(page)
    
            outfile.close()

            self.table_row(outfd, proc.p_pid, 
                           map.start,
                           map.end, 
                           map.end - map.start, 
                           file_path)

    def _read_addr_range(self, proc, start, end):
        pagesize = 4096 

        # set the as with our new dtb so we can read from userland
        proc_as = proc.get_process_address_space()

        while start < end:
            page = proc_as.zread(start, pagesize)
            yield page
            start = start + pagesize
