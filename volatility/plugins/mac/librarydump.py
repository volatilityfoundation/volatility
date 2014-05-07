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

class mac_librarydump(mac_tasks.mac_tasks):
    """ Dumps the executable of a process """

    def __init__(self, config, *args, **kwargs):         
        mac_tasks.mac_tasks.__init__(self, config, *args, **kwargs)         
        self._config.add_option('BASE', short_option = 'b', default = None, help = 'Dump driver with BASE address (in hex)', action = 'store', type = 'int')
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

    def _get_executable_contents(self, proc, address):
        text_map = None

        proc_as = proc.get_process_address_space()

        m = obj.Object("macho_header", offset = address, vm = proc_as)

        buffer = ""
        last_map = None

        print "address: %x m: %s" % (address, m)

        for seg in m.segments():
            if str(seg.segname) == "__PAGEZERO":
                continue

            print "%s | %x" % (str(seg.segname), seg.vmaddr)
            
            if last_map:
                pad_amt = map.start - last_map.end
                pad = "\x00" * pad_amt
            else:
                pad = ""

            buffer = buffer + pad + proc_as.zread(m.obj_offset + seg.vmaddr, seg.filesize)
 
        return buffer
 
    def _write_file(self, proc, exe_address):
        exe_contents = self._get_executable_contents(proc, exe_address)
    
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
                    addresses.append(map.start)
 
            for address in addresses:
                file_path = self._write_file(proc, address)
                self.table_row(outfd, proc.p_comm, proc.p_pid, address, file_path)


