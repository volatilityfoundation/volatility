# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2012 Jamie Levy (Gleeda) <jamie@memoryanalysis.net>
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
@author:       Jamie Levy (Gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie@memoryanalysis.net
@organization: Volatility Foundation
"""

import volatility.debug as debug
import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
import volatility.win32.hive as hivemod
import volatility.utils as utils
import volatility.obj as obj
import os

class DumpRegistry(common.AbstractWindowsCommand):
    ''' Dumps registry files out to disk '''
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o', default = None,
                          help = 'Hive offset (virtual)', 
                          action = 'store', type = 'int')
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                      cache_invalidator = False,
                      help = 'Directory in which to dump extracted files')

    def fixname(self, name, offset):
        name = name.split("\\")[-1].strip()
        name = name.replace(".", "") 
        name = name.replace("/", "")
        name = name.replace(" ", "_")
        name = name.replace("[", "")
        name = name.replace("]", "")
        name = "registry.0x{0:x}.{1}.reg".format(offset, name)
        return name
        

    def calculate(self):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        addr_space = utils.load_as(self._config)
        if self._config.HIVE_OFFSET:
            name = obj.Object("_CMHIVE", vm = addr_space, offset = self._config.HIVE_OFFSET).get_name()
            yield self.fixname(name, self._config.HIVE_OFFSET), hivemod.HiveAddressSpace(addr_space, self._config, self._config.HIVE_OFFSET)
        else:
            regapi = registryapi.RegistryApi(self._config)
            for offset in regapi.all_offsets:
                name = self.fixname(regapi.all_offsets[offset], offset)
                yield name, hivemod.HiveAddressSpace(addr_space, self._config, offset)


    def render_text(self, outfd, data):
        header = "*" * 50
        for name, hive in data:
            of_path = os.path.join(self._config.DUMP_DIR, name.split("\\")[-1].strip())
            regout = open(of_path, "wb")

            outfd.write("{0}\n".format(header))
            outfd.write("Writing out registry: {0}\n\n".format(name))

            hive.save(regout, outfd)
            regout.close()
    
            outfd.write("{0}\n".format(header))
