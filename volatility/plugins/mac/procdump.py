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

class mac_procdump(mac_tasks.mac_tasks):
    """ Dumps the executable of a process """

    def __init__(self, config, *args, **kwargs):         
        mac_tasks.mac_tasks.__init__(self, config, *args, **kwargs)         
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

    def _text_map(self, proc):
        text_map = None

        wanted_vnode = proc.p_textvp.v()

        for map in proc.get_proc_maps():
            vnode = map.get_vnode()

            if vnode and vnode != "sub_map" and vnode.v() == wanted_vnode:
                text_map = map.start.v()
                break

        return text_map

    def get_executable_contents(self, proc, exe_address, path):
        proc_as = proc.get_process_address_space()

        m = obj.Object("macho_header", offset = exe_address, vm = proc_as)

        buffer = ""

        for seg in m.segments():
            if str(seg.segname) == "__PAGEZERO":
                continue
                
            # this is related to the shared cache map 
            # contact Andrew for full details
            if str(seg.segname) == "__LINKEDIT" and seg.vmsize > 20000000:
                continue

            cur = seg.vmaddr
            end = seg.vmaddr + seg.vmsize
        
            while cur < end:
                buffer = buffer + proc_as.zread(cur, 4096) 
                cur = cur + 4096
 
        return buffer
 
    def render_text(self, outfd, data):
        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")
 
        self.table_header(outfd, [("Task", "25"), 
                                  ("Pid", "6"),
                                  ("Address", "[addrpad]"),
                                  ("Path", "")])
       
        for proc in data:
            exe_address = self._text_map(proc)
            
            if exe_address == None:
                continue

            if not exe_address:
                exe_contents = ""
            else:
                exe_contents = self.get_executable_contents(proc, exe_address, "main")
           
            file_name = "task.{0}.{1:#x}.dmp".format(proc.p_pid, exe_address)
            file_path = os.path.join(self._config.DUMP_DIR, file_name)

            outfile = open(file_path, "wb+")
            outfile.write(exe_contents)            
            outfile.close()

            self.table_row(outfd, proc.p_comm, proc.p_pid, exe_address, file_path)


