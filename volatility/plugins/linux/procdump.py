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

class linux_procdump(linux_pslist.linux_pslist):
    """Dumps a process's executable image to disk"""

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

    def _procexedump(self, task, proc_as, elf_addr):
        sects = {}
        ret = ""
        use_rel = False        

        elf_hdr = obj.Object("elf_hdr", offset = elf_addr, vm = proc_as)

        for phdr in elf_hdr.program_headers():

            if str(phdr.p_type) != 'PT_LOAD':
                continue

            start = phdr.p_vaddr
            
            if start == 0:
                use_rel = True
            
            if use_rel:
                start = start + elf_addr
    
            sz    = phdr.p_memsz

            end = start + sz

            if start % 4096:
                start = start & ~0xfff

            if end % 4096:
                end = (end & ~0xfff) + 4096

            real_size = end - start

            # print "addr: %8x sz: %8x offset: %8x sz: %8x" % (phdr.p_vaddr, phdr.p_memsz, phdr.p_offset, phdr.p_filesz),
            # print " | start: %8x sz: %8x end: %8x real_size: %8x" % (start, sz, end, real_size)

            sects[start] = real_size
 
        last_end = -1

        for start in sorted(sects.keys()):
            read_size = sects[start]

            if last_end != -1 and last_end != start + read_size:
                debug.error("busted LOAD segments in %s | %d -> %x != %x + %x" % (task.comm, task.pid, last_end, start, read_size))

            buf = proc_as.zread(start, read_size)

            ret = ret + buf

        return ret

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

            elf_addr = task.mm.start_code

            file_path = os.path.join(self._config.DUMP_DIR, "%s.%d.%#8x" % (task.comm, task.pid, elf_addr))

            file_contents = self._procexedump(task, proc_as, elf_addr)
    
            fd = open(file_path, "wb")
            fd.write(file_contents)
            fd.close()        

            self.table_row(outfd, task.obj_offset,
                                  task.comm,
                                  str(task.pid),
                                  elf_addr, 
                                  file_path)

