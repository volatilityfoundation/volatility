# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# Additional Authors:
# Mike Auty <mike.auty@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

import os
import re
import volatility.plugins.procdump as procdump
import volatility.win32.tasks as tasks
import volatility.debug as debug
import volatility.utils as utils
import volatility.cache as cache
import volatility.exceptions as exceptions

class DLLDump(procdump.ProcExeDump):
    """Dump DLLs from a process address space"""

    def __init__(self, config, *args, **kwargs):
        procdump.ProcExeDump.__init__(self, config, *args, **kwargs)
        config.remove_option("OFFSET")
        config.add_option('REGEX', short_option = 'r',
                      help = 'Dump dlls matching REGEX',
                      action = 'store', type = 'string')
        config.add_option('IGNORE-CASE', short_option = 'i',
                      help = 'Ignore case in pattern match',
                      action = 'store_true', default = False)
        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = 'Dump DLLs for Process with physical address OFFSET',
                          action = 'store', type = 'int')
        config.add_option('BASE', short_option = 'b', default = None,
                          help = 'Dump DLLS at the specified BASE offset in the process address space',
                          action = 'store', type = 'int')

    @cache.CacheDecorator(lambda self: "tests/dlldump/regex={0}/ignore_case={1}/offset={2}/base={3}".format(self._config.REGEX, self._config.IGNORE_CASE, self._config.OFFSET, self._config.BASE))
    def calculate(self):
        addr_space = utils.load_as(self._config)

        if self._config.OFFSET != None:
            data = [self.virtual_process_from_physical_offset(addr_space, self._config.OFFSET)]
        else:
            data = self.filter_tasks(tasks.pslist(addr_space))

        if self._config.REGEX:
            try:
                if self._config.IGNORE_CASE:
                    mod_re = re.compile(self._config.REGEX, re.I)
                else:
                    mod_re = re.compile(self._config.REGEX)
            except re.error, e:
                debug.error('Error parsing regular expression: %s' % e)

        for proc in data:
            ps_ad = proc.get_process_address_space()
            if ps_ad == None:
                continue

            mods = dict((mod.DllBase.v(), mod) for mod in proc.get_load_modules())

            if self._config.BASE:
                if mods.has_key(self._config.BASE):
                    mod_name = mods[self._config.BASE].BaseDllName
                else:
                    mod_name = "UNKNOWN"
                yield proc, ps_ad, int(self._config.BASE), mod_name
            else:
                for mod in mods.values():
                    if self._config.REGEX:
                        if not mod_re.search(str(mod.FullDllName)) and not mod_re.search(str(mod.BaseDllName)):
                            continue
                    yield proc, ps_ad, mod.DllBase.v(), mod.BaseDllName

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for proc, ps_ad, mod_base, mod_name in data:
            if ps_ad.is_valid_address(mod_base):
                process_offset = ps_ad.vtop(proc.obj_offset)
                dump_file = "module.{0}.{1:x}.{2:x}.dll".format(proc.UniqueProcessId, process_offset, mod_base)
                outfd.write("Dumping {0}, Process: {1}, Base: {2:8x} output: {3}\n".format(mod_name, proc.ImageFileName, mod_base, dump_file))
                of = open(os.path.join(self._config.DUMP_DIR, dump_file), 'wb')
                try:
                    for chunk in self.get_image(outfd, ps_ad, mod_base):
                        offset, code = chunk
                        of.seek(offset)
                        of.write(code)
                except ValueError, ve:
                    outfd.write("Unable to dump executable: {0}\n".format(ve))
                except exceptions.SanityCheckException, ve:
                    outfd.write("Unable to dump executable: {0}\n".format(ve))
                    outfd.write("You can use -u to disable this check.\n")
                of.close()
            else:
                outfd.write("Cannot dump {0}@{1}: ImageBase at {2:8x} is paged\n".format(proc.ImageFileName, mod_name, mod_base))
