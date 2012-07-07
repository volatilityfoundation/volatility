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
import volatility.cache as cache
import volatility.win32.modules as modules
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.exceptions as exceptions

class ModDump(procdump.ProcExeDump):
    """Dump a kernel driver to an executable file sample"""

    def __init__(self, config, *args, **kwargs):
        procdump.ProcExeDump.__init__(self, config, *args, **kwargs)
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
                debug.error('Error parsing regular expression: %s' % e)

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
                    if not mod_re.search(str(mod.FullDllName)) and not mod_re.search(str(mod.BaseDllName)):
                        continue
                yield addr_space, procs, mod.DllBase.v(), mod.BaseDllName

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for addr_space, procs, mod_base, mod_name in data:
            space = tasks.find_space(addr_space, procs, mod_base)
            if space != None:
                dump_file = "driver.{0:x}.sys".format(mod_base)
                outfd.write("Dumping {0}, Base: {1:8x} output: {2}\n".format(mod_name, mod_base, dump_file))
                of = open(os.path.join(self._config.DUMP_DIR, dump_file), 'wb')
                try:
                    for chunk in self.get_image(outfd, space, mod_base):
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
                outfd.write("Cannot dump {0} at {1:8x}\n".format(mod_name, mod_base))
