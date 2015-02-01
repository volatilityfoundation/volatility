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
import volatility.plugins.mac.pstasks as pstasks 
import volatility.plugins.mac.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_notesapp(pstasks.mac_tasks):
    """ Finds contents of Notes messages """

    def __init__(self, config, *args, **kwargs):         
        pstasks.mac_tasks.__init__(self, config, *args, **kwargs)         
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')
 
    def calculate(self):
        common.set_plugin_members(self)

        procs = pstasks.mac_tasks.calculate(self)

        for proc in procs:
            if str(proc.p_comm).lower().find("notes") == -1:
                continue

            proc_as = proc.get_process_address_space()

            for map in proc.get_proc_maps():
                if map.get_perms() != "rw-" or map.get_path() != "":
                    continue

                buffer = proc_as.zread(map.start.v(), map.end.v() - map.start.v())

                if not buffer:
                    continue

                iter_idx = 0

                while 1:
                    idx = buffer[iter_idx:].find("<html>")
                    if idx == -1:
                        break

                    iter_idx = iter_idx + idx

                    end_idx = buffer[iter_idx:].find("</html>")
                    if end_idx == -1:
                        break
 
                    msg = buffer[iter_idx:iter_idx + end_idx + 7]
                    
                    yield proc, map.start.v() + iter_idx, msg
                    
                    iter_idx = iter_idx + end_idx
                        
                    
    def unified_output(self, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        return TreeGrid([("Pid", int),
                          ("Name", str),
                          ("Start", Address),
                          ("Size", str),
                          ("Path", str),
                          ], self.generator(data))

    def generator(self, data):
        for (proc, start, msg) in data:
            fname = "Notes.{0}.{1:x}.txt".format(proc.p_pid, start)
            file_path = os.path.join(self._config.DUMP_DIR, fname)            

            fd = open(file_path, "wb+")
            fd.write(msg)
            fd.close()

            yield(0,[
                    int(proc.p_pid),
                    str(proc.p_comm),
                    Address(start),
                    str(len(msg)),
                    str(file_path),
                    ])



