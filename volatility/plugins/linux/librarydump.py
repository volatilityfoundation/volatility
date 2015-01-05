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
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.procdump as linux_procdump

class linux_librarydump(linux_pslist.linux_pslist):
    """Dumps shared libraries in process memory to disk"""

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')
        self._config.add_option('BASE', short_option = 'b', default = None, help = 'Dump driver with BASE address (in hex)', action = 'store', type = 'int')

    def render_text(self, outfd, data):
        if not self._config.DUMP_DIR:
            debug.error("-D/--dump-dir must given that specifies an existing directory")

        self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Name", "20"),
                                  ("Pid", "15"),
                                  ("Address", "[addrpad]"),
                                  ("Output File", "")])
        for task in data:
            if not task.mm:
                continue
   
            proc_as = task.get_process_address_space()
 
            for vma in task.get_proc_maps():
                if self._config.BASE and vma.vm_start != self._config.BASE:
                    continue
            
                elf_addr = vma.vm_start

                buf = proc_as.zread(elf_addr, 4)

                if buf != "\x7fELF":
                    continue
            
                file_path = linux_common.write_elf_file(self._config.DUMP_DIR, task, elf_addr)

                self.table_row(outfd, task.obj_offset,
                                      task.comm,
                                      str(task.pid),
                                      elf_addr, 
                                      file_path)

