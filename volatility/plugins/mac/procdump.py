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

    def _get_executable_contents(self, proc):
        text_map = None

        proc_as = proc.get_process_address_space()

        wanted_vnode = proc.p_textvp.v()

        for map in proc.get_proc_maps():
            vnode = map.get_vnode()

            if vnode and vnode != "sub_map" and vnode.v() == wanted_vnode:
                text_map = map
                break

        if text_map == None:
            return (0, "")

        m = obj.Object("macho_header", offset = text_map.start, vm = proc_as)

        buffer = ""
        last_map = None
        first_vmaddr = 0

        for seg in m.segments():
            if str(seg.segname) == "__PAGEZERO":
                continue

            if last_map:
                pad_amt = map.start - last_map.end
                pad = "\x00" * pad_amt
            else:
                pad = ""

            vstart = seg.vmaddr
            if first_vmaddr == 0:
                first_vmaddr = seg.vmaddr

            if vstart < text_map.start:
                vstart = vstart + text_map.start - first_vmaddr

            print "getting for segment: %s | %x | %x | %x | %d" % (seg.segname, vstart, seg.vmaddr, text_map.start, seg.filesize)
            buffer = buffer + pad + proc_as.zread(vstart, seg.filesize)
 
        return (text_map.start, buffer)
 
    def bad_get_executable_contents(self, proc):
        maps = []

        proc_as = proc.get_process_address_space()

        wanted_vnode = proc.p_textvp.v()

        for map in proc.get_proc_maps():
            vnode = map.get_vnode()

            if vnode and vnode != "sub_map" and vnode.v() == wanted_vnode:
                maps.append(map)            

        buffer = ""
        last_map = None
        for map in maps:
            if last_map:
                pad_amt = map.start - last_map.end
                pad = "\x00" * pad_amt
            else:
                pad = ""

            buffer = buffer + pad + proc_as.zread(map.start, map.end - map.start)

            last_map = map

        return (maps[0].start, buffer)

    def render_text(self, outfd, data):
        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")
 
        self.table_header(outfd, [("Task", "25"), 
                                  ("Pid", "6"),
                                  ("Address", "[addrpad]"),
                                  ("Path", "")])
       
        for proc in data:
            (exe_address, exe_contents) = self._get_executable_contents(proc)
            
            if exe_contents == "":
                continue

            file_name = "task.{0}.{1:#x}.dmp".format(proc.p_pid, exe_address)
            file_path = os.path.join(self._config.DUMP_DIR, file_name)

            outfile = open(file_path, "wb+")
            outfile.write(exe_contents)            
            outfile.close()

            self.table_row(outfd, proc.p_comm, proc.p_pid, exe_address, file_path)


