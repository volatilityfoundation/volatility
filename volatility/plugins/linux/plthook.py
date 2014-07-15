# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2014 CrowdStrike, Inc.
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
@author:       Georg Wicherski
@license:      GNU General Public License 2.0
@contact:      georg@crowdstrike.com
@organization: CrowdStrike, Inc.
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.elfs as linux_elfs

class linux_plthook(linux_elfs.linux_elfs):
    """Scan ELF binaries' PLT for hooks to non-NEEDED images"""

    def __init__(self, config, *args, **kwargs):
        linux_elfs.linux_elfs.__init__(self, config, *args, **kwargs)
        self._config.add_option( \
                'ALL', short_option = 'a', default = False,
                help = 'Display all PLT slots (incl. not hooked)', action = 'store_true')
        self._config.add_option( \
                'IGNORE', default = [ ],
                help = 'Ignore mappings backed by this path, ' \
                        +' useful for bad -l compiles (i.e. apache2 modules)',
                        action = 'append')

    def calculate(self):
        linux_common.set_plugin_members(self)
        elfs = dict()
        ignore = frozenset(self._config.IGNORE)

        for task, elf, elf_start, elf_end, soname, needed in linux_elfs.linux_elfs.calculate(self):
            elfs[(task, soname)] = (elf, elf_start, elf_end, needed)

        for k, v in elfs.iteritems():
            task, soname = k
            elf, elf_start, elf_end, needed = v
          
            if elf._get_typename("hdr") == "elf32_hdr":
                elf_arch = 32
            else:
                elf_arch = 64
         
            needed_expanded = set([soname])
            if (task, None) in elfs:
                needed_expanded.add(None)
            # jmp slot can point to ELF itself if the fn hasn't been called yet (RTLD_LAZY)
            # can point to main binary (None above) if this is a plugin-style symbol
            while len(needed) > 0:
                dep = needed.pop(0)
                needed_expanded.add(dep)
                try:
                    needed += set(elfs[(task, dep)][3]) - needed_expanded
                except KeyError:
                    needed_expanded.remove(dep)

            for reloc in elf.relocations():
                rsym = elf.relocation_symbol(reloc)

                if rsym == None:
                    continue

                symbol_name = elf.symbol_name(rsym)
                if symbol_name == None:
                    symbol_name = "<N/A>"

                offset = reloc.r_offset
               
                if offset < elf_start:
                    offset = elf_start + offset

                if elf_arch == 32:
                    addr = obj.Object("unsigned int", offset = offset, vm = elf.obj_vm)
                else:
                    addr = obj.Object("unsigned long long", offset = offset, vm = elf.obj_vm)
                
                match = False
                for dep in needed_expanded:
                    _, dep_start, dep_end, _ = elfs[(task, dep)]
                    if addr >= dep_start and addr < dep_end:
                        match = dep

                hookdesc = ''
                vma = None
                for i in task.get_proc_maps():
                    if addr >= i.vm_start and addr < i.vm_end:
                        vma = i
                        break                    
                if vma:
                    if vma.vm_file:
                        hookdesc = linux_common.get_path(task, vma.vm_file)

                        if hookdesc in ignore:
                            continue
                    else:
                        hookdesc = '[{0:x}:{1:x},{2}]'.format(vma.vm_start, vma.vm_end, vma.vm_flags)
 
                if hookdesc == "":
                        hookdesc = 'invalid memory'
                
                if match != False:
                    if self._config.ALL and match == soname:
                        hookdesc = '[RTLD_LAZY]'
                    hooked = False 
                
                else:
                    hooked = True

                yield task, soname, elf, elf_start, elf_end, addr, symbol_name, hookdesc, hooked

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Task", "10"), 
                                  ("ELF Start", "[addrpad]"), 
                                  ("ELF Name", "24"),
                                  ("Symbol", "24"),
                                  ("Resolved Address", "[addrpad]"),
                                  ("H", "1"),
                                  ("Target Info", "")])

        for task, soname, elf, elf_start, elf_end, addr, imp, info, hooked in data:
            if not hooked and not self._config.ALL:
                continue

            self.table_row(outfd, task.pid, elf_start, soname if soname else '[main]', \
                    imp, addr, '!' if hooked else ' ', info)
