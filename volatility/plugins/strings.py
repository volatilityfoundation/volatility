# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2009 Timothy D. Morgan (strings optimization)
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

import os
import volatility.win32 as win32
import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.plugins.taskmods as taskmods
import volatility.plugins.filescan as filescan
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class Strings(common.AbstractWindowsCommand):
    """Match physical offsets to virtual addresses (may take a while, VERY verbose)"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('STRING-FILE', short_option = 's', default = None,
                          help = 'File output in strings format (offset:string)',
                          action = 'store', type = 'str')
        config.add_option("SCAN", short_option = 'S', default = False,
                          action = 'store_true', help = 'Use PSScan if no offset is provided')
        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = 'EPROCESS offset (in hex) in the physical address space',
                          action = 'store', type = 'int')
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')
        config.add_option('LOOKUP-PID', short_option = 'L', default = False,
                          action = 'store_true', help = 'Lookup the ImageFileName of PIDs')
  
    def get_processes(self, addr_space):
        """Enumerate processes based on user options.

        :param      addr_space | <addrspace.AbstractVirtualAddressSpace>

        :returns    <list> 
        """

        bounce_back = taskmods.DllList.virtual_process_from_physical_offset
        if self._config.OFFSET != None:
            tasks = [bounce_back(addr_space, self._config.OFFSET)]
        elif self._config.SCAN:
            procs = list(filescan.PSScan(self._config).calculate())
            tasks = []
            for task in procs:
                tasks.append(bounce_back(addr_space, task.obj_offset))
        else:
            tasks = win32.tasks.pslist(addr_space)

        try:
            if self._config.PID is not None:
                pidlist = [int(p) for p in self._config.PID.split(',')]
                tasks = [t for t in tasks if int(t.UniqueProcessId) in pidlist]
        except (ValueError, TypeError):
            debug.error("Invalid PID {0}".format(self._config.PID))

        return tasks

    @classmethod
    def get_modules(cls, addr_space):    
        """Enumerate the kernel modules. 

        :param      addr_space | <addrspace.AbstractVirtualAddressSpace>
        
        :returns    <tuple>
        """
        
        modules = win32.modules.lsmod(addr_space)
        mask = addr_space.address_mask
        mods = dict((mask(mod.DllBase), mod) for mod in modules)
        mod_addrs = sorted(mods.keys())
         
        return (mods, mod_addrs)

    @classmethod
    def find_module(cls, mods, mod_addrs, addr_space, vpage):
        """Determine which module owns a virtual page. 

        :param      mods        | <list>
                    mod_addrs   | <list>
                    addr_space  | <addrspace.AbstractVirtualAddressSpace>
                    vpage       | <int> 
        
        :returns    <_LDR_DATA_TABLE_ENTRY> || None
        """
        
        mask = addr_space.address_mask
        return win32.tasks.find_module(mods, mod_addrs, mask(vpage))

    @classmethod
    def get_module_name(cls, module):
        """Get the name of a kernel module.

        :param      module      | <_LDR_DATA_TABLE_ENTRY>
        
        :returns    <str>
        """

        return str(module.BaseDllName or '')

    @classmethod
    def get_task_pid(cls, task):
        """Get the PID of a process. 

        :param      task   | <_EPROCESS>
        
        :returns    <int>
        """

        return task.UniqueProcessId

    def calculate(self):

        if (self._config.STRING_FILE is None or 
                    not os.path.exists(self._config.STRING_FILE)):
            debug.error("Strings file not found")

        addr_space = utils.load_as(self._config)

        layers = [addr_space]
        base = addr_space.base
        while base:
            layers.append(base)
            base = base.base 

        if len(layers) > 2:
            debug.error("Raw memory needed, got {0} (convert with imagecopy)".format(layers[1].__class__.__name__))

        tasks = self.get_processes(addr_space)

        stringlist = open(self._config.STRING_FILE, "r")
        reverse_map = self.get_reverse_map(addr_space, tasks)

        for line in stringlist:
            try:
                (offsetString, string) = self.parse_line(line)
                offset = int(offsetString)
            except ValueError:
                debug.error("String file format invalid.")

            pids = ["FREE MEMORY:-1"]
            if reverse_map.has_key(offset & 0xFFFFFFFFFFFFF000):
                if self._config.LOOKUP_PID:
                    pids = ["{0}{2}:{1:08x}".format(
                        pid[0],
                        pid[2] | (offset & 0xFFF),
                        '' if not pid[1] else '={}'.format(pid[1])
                    ) for pid in reverse_map[offset & 0xFFFFFFFFFFFFF000][1:]]
                else:
                    pids = ["{0}:{1:08x}".format(
                        pid[0],
                        pid[2] | (offset & 0xFFF)
                    ) for pid in reverse_map[offset & 0xFFFFFFFFFFFFF000][1:]]

            yield offset, pids, "{0}".format(string.strip())

    @classmethod
    def parse_line(cls, line):
        """Parses a line of strings. 

        :param      cls     | <Strings>
                    line    | <str>
        
        :returns    <tuple>
        """
        # Remove any leading spaces to handle nasty strings output
        line = line.lstrip()
        maxlen = len(line)
        split_char = ' '
        for char in [' ', ':']:
            charpos = line.find(char)
            if charpos < maxlen and charpos > 0:
                split_char = char
                maxlen = charpos
        return tuple(line.split(split_char, 1))

    @classmethod
    def get_reverse_map(cls, addr_space, tasks):
        """Generates a reverse mapping of physical addresses 
        to the kernel and/or tasks.

        :param      addr_space  | <addrspace.AbstractVirtualAddressSpace>
                    tasks       | <list> 
    
        :returns    <dict>
        """

        # ASSUMPTION: no pages mapped in kernel and userland
        # XXX: Can we eliminate the above assumption?  It seems like the only change needed for
        #      that would be to store a boolean with each pid/vaddr pair...
        #
        # XXX: The following code still fails to represent information about larger pages in
        #      the final output.  The output implies that addresses in a large page are
        #      really stored in one or more 4k pages.  This is no different from the old
        #      version of the code, but in this version it could be corrected easily by
        #      recording vpage instead of vpage+i in the reverse map. -- TDM
        reverse_map = {}

        (mods, mod_addrs) = cls.get_modules(addr_space)
   
        debug.debug("Calculating kernel mapping...\n")
        available_pages = addr_space.get_available_pages()
        for (vpage, vpage_size) in available_pages:
            kpage = addr_space.vtop(vpage)
            for i in range(0, vpage_size, 0x1000):
                # Since the output will always be mutable, we 
                # don't need to reinsert into the list
                pagelist = reverse_map.get(kpage + i, None)
                if pagelist is None:
                    pagelist = [True]
                    reverse_map[kpage + i] = pagelist
                # Try to lookup the owning kernel module
                module = cls.find_module(mods, mod_addrs, addr_space, vpage + i)
                if module:
                    hint = cls.get_module_name(module)
                else:
                    hint = 'kernel'
                pagelist.append((hint, None, vpage + i))  # None is placeholder (used by tasks)

        debug.debug("Calculating task mappings...\n")
        for task in tasks:
            task_space = task.get_process_address_space()
            debug.debug("  Task {0} ...".format(cls.get_task_pid(task)))
            process_id = cls.get_task_pid(task)
            try:
                available_pages = task_space.get_available_pages()
                for (vpage, vpage_size) in available_pages:
                    physpage = task_space.vtop(vpage)
                    for i in range(0, vpage_size, 0x1000):
                        # Since the output will always be mutable, we 
                        # don't need to reinsert into the list
                        pagelist = reverse_map.get(physpage + i, None)
                        if pagelist is None:
                            pagelist = [False]
                            reverse_map[physpage + i] = pagelist
                        if not pagelist[0]:
                            pagelist.append((process_id, task.ImageFileName, vpage + i))

            except (AttributeError, ValueError, TypeError):
                # Handle most errors, but not all of them
                continue
        
        return reverse_map

    def unified_output(self, data):
        return TreeGrid([("Offset(P)", Address),
                       ("Attribution", str),
                       ("Offset(V)", Address),
                       ("String", str)],
                        self.generator(data))

    def generator(self, data):
        for offset, pids, string in data:
            for p in pids:
                item, addr = p.split(":")
                yield (0, [Address(offset),
                        str(item),
                        Address(int(addr, 16)),
                        str(string)])

    def render_text(self, outfd, data):
        for offset, pids, string in data:
            outfd.write("{0} [{1}] {2}\n".format(offset, ' '.join(pids), string))

