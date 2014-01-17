# Volatility
# Copyright (c) 2012 Michael Ligh (michael.ligh@mnin.org)
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

import volatility.plugins.taskmods as taskmods
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.plugins.filescan as filescan
import volatility.plugins.modscan as modscan

class EnumFunc(taskmods.DllList):
    """Enumerate imported/exported functions"""

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.remove_option("PID")
        config.remove_option("OFFSET")
        config.add_option("SCAN", short_option = 's', default = False,
                          action = 'store_true', help = 'Scan for objects')
        config.add_option("PROCESS-ONLY", short_option = 'P', default = False,
                          action = 'store_true', help = 'Process only')
        config.add_option("KERNEL-ONLY", short_option = 'K', default = False,
                          action = 'store_true', help = 'Kernel only')
        config.add_option("IMPORT-ONLY", short_option = 'I', default = False,
                          action = 'store_true', help = 'Imports only')
        config.add_option("EXPORT-ONLY", short_option = 'E', default = False,
                          action = 'store_true', help = 'Exports only')

    def calculate(self):
        addr_space = utils.load_as(self._config)

        tasklist = []
        modslist = []

        if self._config.SCAN:
            if not self._config.KERNEL_ONLY:
                for t in filescan.PSScan(self._config).calculate():
                    v = self.virtual_process_from_physical_offset(addr_space, t.obj_offset)
                    if v:
                        tasklist.append(v)
            if not self._config.PROCESS_ONLY:
                modslist = [m for m in modscan.ModScan(self._config).calculate()]
        else:
            if not self._config.KERNEL_ONLY:
                tasklist = [t for t in tasks.pslist(addr_space)]
            if not self._config.PROCESS_ONLY:
                modslist = [m for m in modules.lsmod(addr_space)]

        for task in tasklist:
            for mod in task.get_load_modules():
                yield task, mod

        for mod in modslist:
            yield None, mod

    def render_text(self, outfd, data):

        outfd.write("{0:<20} {1:<10} {2:<20} {3:<10} {4:<20} {5}\n".format(
                "Process", "Type", "Module", "Ordinal", "Address", "Name"))

        for process, module in data:
            if not self._config.IMPORT_ONLY:
                for o, f, n in module.exports():
                    outfd.write("{0:<20} {1:<10} {2:<20} {3:<10} {4:#018x} {5}\n".format(
                            process.ImageFileName if process else "<KERNEL>",
                            "Export", module.BaseDllName,
                            o,
                            (module.DllBase + f) if f else 0, # None if forwarded 
                            n or '' # None if paged
                            ))
            if not self._config.EXPORT_ONLY:
                for dll, o, f, n in module.imports():
                    outfd.write("{0:<20} {1:<10} {2:<20} {3:<10} {4:#018x} {5}\n".format(
                            process.ImageFileName if process else "<KERNEL>",
                            "Import", module.BaseDllName,
                            o,
                            f or 0, # None if paged 
                            dll + "!" + n or '' # None if paged or imported by ordinal 
                            ))
