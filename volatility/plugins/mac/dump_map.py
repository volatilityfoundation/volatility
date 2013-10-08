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

import os
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.mac.proc_maps as proc_maps

class mac_dump_maps(proc_maps.mac_proc_maps):
    """ Dumps memory ranges of processes """

    def __init__(self, config, *args, **kwargs):         
        proc_maps.mac_proc_maps.__init__(self, config, *args, **kwargs)         
        self._config.add_option('MAP_ADDRESS', short_option = 's', default = None, help = 'Filter by starting address of map', action = 'store', type = 'long') 
        self._config.add_option('OUTPUTFILE', short_option = 'O', default = None, help = 'Output File', action = 'store', type = 'str')
    
    def render_text(self, outfd, data):
        if not self._config.OUTPUTFILE:
            debug.error("Please specify an OUTPUTFILE")
        elif os.path.exists(self._config.OUTPUTFILE):
            debug.error("Cowardly refusing to overwrite an existing file")
                    
        outfile = open(self._config.OUTPUTFILE, "wb+")
        map_address = self._config.MAP_ADDRESS

        size = 0
        for proc, map in data:
            if not map_address or map_address == map.links.start:
                for page in self._read_addr_range(proc, map.links.start, map.links.end):
                    size += len(page)
                    outfile.write(page)
        
        outfile.close()
        outfd.write("Wrote {0} bytes\n".format(size))

    def _read_addr_range(self, proc, start, end):
        pagesize = 4096 

        # set the as with our new dtb so we can read from userland
        proc_as = proc.get_process_address_space()

        while start < end:
            page = proc_as.zread(start, pagesize)
            yield page
            start = start + pagesize
