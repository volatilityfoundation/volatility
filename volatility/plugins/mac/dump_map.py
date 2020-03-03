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
@author:       Andrew Case and Golden G. Richard III
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com / golden@arcanealloy.com
@organization: 
"""

import os
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.mac.common as common
import volatility.plugins.mac.pstasks as pstasks 

class mac_dump_maps(pstasks.mac_tasks):
    """ Dumps memory ranges of process(es) """

    def __init__(self, config, *args, **kwargs):         
        pstasks.mac_tasks.__init__(self, config, *args, **kwargs)         
        self._config.add_option('MAP-ADDRESS', short_option = 's', default = None, help = 'Filter by starting address of map', action = 'store', type = 'long') 
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None,
                      cache_invalidator = False,
                      help = 'Directory in which to dump extracted files')

        # don't try to deal with maps larger than this--just skip them
        self.MAXMAPSIZE = 1000000000

    def render_text(self, outfd, data):
        common.set_plugin_members(self)
        if not self._config.DUMP_DIR:
            debug.error("Please specify an output directory.")
        elif not os.path.exists(self._config.DUMP_DIR):
            debug.error("Please specify a directory that exists.")
                    
        map_address = self._config.MAP_ADDRESS

        self.table_header(outfd, [("Pid", "8"), 
                          ("Name", "20"),
                          ("Map Name", "8"),
                          ("Output Size", ""),
                          ("Output Path", "")])

        for proc in data:
            pas = proc.get_process_address_space()
            if pas == None:
                continue

            pid = proc.p_pid
            if pid == 0:
                continue
            
            pname = str(proc.p_comm)

            for map in proc.get_proc_maps():
                start  = map.links.start.v()
                end    = map.links.end.v()
                length = end - start

                if map_address != None and map_address != start:
                    continue        

                if length > self.MAXMAPSIZE:
                    outfd.write("Skipping suspiciously large map, smearing is suspected.  Adjust MAXMAPSIZE to override.\n")
                    continue
                
                fname = "%d.%#x.%#x.dmp" % (pid, start, end)
                of_path = os.path.join(self._config.DUMP_DIR, fname)
                outfile = open(of_path, "wb")
            
                written_size = 0

                for addr in range(start, end, 4096):
                    page = pas.zread(addr, 4096)
                    outfile.write(page)
                    written_size = written_size + 4096

                outfile.close()

                self.table_row(outfd, 
                           pid, 
                           pname,
                           map.get_path(),
                           written_size,
                           of_path)

