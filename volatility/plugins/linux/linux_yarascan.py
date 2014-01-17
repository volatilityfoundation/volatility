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

import volatility.plugins.malware.malfind as malfind
import volatility.plugins.linux.pslist as pslist
import volatility.plugins.linux.common as linux_common
import volatility.utils as utils 
import volatility.debug as debug

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

class VmaYaraScanner(malfind.BaseYaraScanner):
    """A scanner over all memory regions of a process."""

    def __init__(self, task = None, **kwargs):
        """Scan the process address space through the VMAs.

        Args:
          task: The task_struct object for this task.
        """
        self.task = task
        malfind.BaseYaraScanner.__init__(self, address_space = task.get_process_address_space(), **kwargs)

    def scan(self, offset = 0, maxlen = None):
        for vma in self.task.get_proc_maps():
            for match in malfind.BaseYaraScanner.scan(self, vma.vm_start, vma.vm_end - vma.vm_start):
                yield match

class linux_yarascan(malfind.YaraScan):
    """A shell in the Linux memory image"""

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'linux'

    def calculate(self):
    
        ## we need this module imported
        if not has_yara:
            debug.error("Please install Yara from code.google.com/p/yara-project")
            
        ## leveraged from the windows yarascan plugin
        rules = self._compile_rules()
            
        ## set the linux plugin address spaces 
        linux_common.set_plugin_members(self)
    
        if self._config.KERNEL:
            ## the start of kernel memory taken from VolatilityLinuxIntelValidAS
            if self.addr_space.profile.metadata.get('memory_model', '32bit') == "32bit":
                kernel_start = 0xc0000000
            else:
                kernel_start = 0xffffffff80000000
            
            scanner = malfind.DiscontigYaraScanner(rules = rules,
                                                   address_space = self.addr_space)
                                                   
            for hit, address in scanner.scan(start_offset = kernel_start):
                yield (None, address, hit, 
                        scanner.address_space.zread(address, 64))
        else:
            for task in pslist.linux_pslist(self._config).calculate():
                scanner = VmaYaraScanner(task = task, rules = rules)
                for hit, address in scanner.scan():
                    yield (task, address, hit, 
                                scanner.address_space.zread(address, 64))
    
    def render_text(self, outfd, data):
        for task, address, hit, buf in data:
            if task:
                outfd.write("Task: {0} pid {1} rule {2} addr {3:#x}\n".format(
                    task.comm, task.pid, hit.rule, address))
            else:
                outfd.write("[kernel] rule {0} addr {1:#x}\n".format(hit.rule, address))
            
            outfd.write("".join(["{0:#010x}  {1:<48}  {2}\n".format(
                address + o, h, ''.join(c)) for o, h, c in utils.Hexdump(buf)]))
