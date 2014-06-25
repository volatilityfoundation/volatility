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

import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_process_hollow(linux_pslist.linux_pslist):
    """Checks for signs of process hollowing"""

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('BASE', short_option = 'b', default = None, help = 'The address of the ELF file in memory', action = 'store', type='long' )
        self._config.add_option('PATH', short_option = 'P', default = None, help = 'The path of the known good file', action = 'store', type='str') 

    # TODO:
    # make aware of if application or library
    # check the class, then do offset + base based on that
    def calculate(self):
        linux_common.set_plugin_members(self)

        if not self._config.BASE:
            debug.error("No base address specified.")

        if not self._config.PATH:
            debug.error("No known-good path specified.")

        fd = open(self._config.PATH, "rb")
        known_good = fd.read()
        fd.close()

        bufferas = addrspace.BufferAddressSpace(self._config, data = known_good)
        elf_hdr = obj.Object("elf_hdr", offset = 0, vm = bufferas)  

        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            proc_as = task.get_process_address_space()

            for vma in task.get_proc_maps():
                if self._config.BASE != vma.vm_start:
                    continue
                
                for sym in elf_hdr.symbols():
                    if sym.st_value == 0 or (sym.st_info & 0xf) != 2:
                        continue

                    symname = elf_hdr.symbol_name(sym)

                    sym_offset = sym.st_value

                    # in the same vma
                    if vma.vm_start < sym.st_value < vma.vm_end:
                        vm_start = vma.vm_start
                        sym_offset = sym_offset - vm_start
                        full_address = sym.st_value
                    else:
                        next_vma = vma.vm_next
                        if next_vma.vm_start < sym.st_value < next_vma.vm_end:
                            vm_start = next_vma.vm_start
                            sym_offset = sym.st_value - vm_start
                            full_address = sym.st_value
                        else:
                            full_address = vma.vm_start + sym.st_value

                    mem_buffer  = proc_as.read(vm_start + sym_offset, sym.st_size)
                    
                    if sym.st_value > vma.vm_start:
                        disk_off = sym.st_value - vm_start
                    else:
                        disk_off = sym.st_value

                    disk_buffer = bufferas.read(disk_off, sym.st_size)

                    # bad
                    if mem_buffer != None and disk_buffer != mem_buffer:
                        yield task, symname, full_address
                    elif mem_buffer == None:
                        print "Function %s paged out in memory" % symname   
     
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Task", "16"),
                                  ("PID", "6"),
                                  ("Symbol Name", "32"),
                                  ("Symbol Address", "[addrpad]"),                 
                                  ])
        for (task, symname, address) in data:
            self.table_row(outfd, str(task.comm), task.pid, symname, address)









