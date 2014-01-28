# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# Additional Authors:
# Mike Auty <mike.auty@gmail.com>
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
import re
import volatility.plugins.procdump as procdump
import volatility.cache as cache
import volatility.win32.modules as modules
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug

class ModDump(procdump.ProcDump):
    """Dump a kernel driver to an executable file sample"""

    def __init__(self, config, *args, **kwargs):
        procdump.ProcDump.__init__(self, config, *args, **kwargs)
        config.remove_option("PID")
        config.remove_option("OFFSET")
        config.add_option('REGEX', short_option = 'r',
                      help = 'Dump modules matching REGEX',
                      action = 'store', type = 'string')
        config.add_option('IGNORE-CASE', short_option = 'i',
                      help = 'Ignore case in pattern match',
                      action = 'store_true', default = False)
        config.add_option('BASE', short_option = 'b', default = None,
                          help = 'Dump driver with BASE address (in hex)',
                          action = 'store', type = 'int')

    @cache.CacheDecorator(lambda self: "tests/moddump/regex={0}/ignore-case={1}/base={2}".format(self._config.REGEX, self._config.IGNORE_CASE, self._config.BASE))
    def calculate(self):
        addr_space = utils.load_as(self._config)

        if self._config.REGEX:
            try:
                if self._config.IGNORE_CASE:
                    mod_re = re.compile(self._config.REGEX, re.I)
                else:
                    mod_re = re.compile(self._config.REGEX)
            except re.error, e:
                debug.error('Error parsing regular expression: {0}'.format(e))

        mods = dict((mod.DllBase.v(), mod) for mod in modules.lsmod(addr_space))
        # We need the process list to find spaces for some drivers. Enumerate them here
        # instead of inside the find_space function, so we only have to do it once. 
        procs = list(tasks.pslist(addr_space))

        if self._config.BASE:
            if mods.has_key(self._config.BASE):
                mod_name = mods[self._config.BASE].BaseDllName
            else:
                mod_name = "UNKNOWN"
            yield addr_space, procs, int(self._config.BASE), mod_name
        else:
            for mod in mods.values():
                if self._config.REGEX:
                    if not mod_re.search(str(mod.FullDllName or '')) and not mod_re.search(str(mod.BaseDllName or '')):
                        continue
                yield addr_space, procs, mod.DllBase.v(), mod.BaseDllName

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        self.table_header(outfd, [("Module Base", "[addrpad]"),
                           ("Module Name", "20"),
                           ("Result", "")])

        for addr_space, procs, mod_base, mod_name in data:
            space = tasks.find_space(addr_space, procs, mod_base)
            if space == None:
                result = "Error: Cannot acquire AS"
            else:
                dump_file = "driver.{0:x}.sys".format(mod_base)
                result = self.dump_pe(space, mod_base, dump_file)
            self.table_row(outfd, mod_base, mod_name, result)
