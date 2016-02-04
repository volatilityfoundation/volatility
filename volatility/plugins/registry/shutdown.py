# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
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
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie@memoryanalysis.net
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

import volatility.plugins.registry.registryapi as registryapi
from volatility.renderers import TreeGrid
import volatility.plugins.common as common
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import datetime
import struct

class ShutdownTime(common.AbstractWindowsCommand):
    "Print ShutdownTime of machine from registry"

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o',
                          help = 'Hive offset (virtual)', type = 'int')
        self.regapi = None

    def calculate(self):
        addr_space = utils.load_as(self._config)
        self.regapi = registryapi.RegistryApi(self._config)
        result = {}

        if not self._config.HIVE_OFFSET:
            self.regapi.set_current("SYSTEM")
        else:
            name = obj.Object("_CMHIVE", vm = addr_space, offset = self._config.HIVE_OFFSET).get_name()
            self.regapi.all_offsets[self._config.HIVE_OFFSET] = name
            self.regapi.current_offsets[self._config.HIVE_OFFSET] = name

        self.regapi.reset_current()
        currentcs = self.regapi.reg_get_currentcontrolset()
        if currentcs == None:
            currentcs = "ControlSet001"

        shutdownkey = currentcs + "\\Control\\Windows"
        key = self.regapi.reg_get_key("system", shutdownkey)
        value = self.regapi.reg_get_value("system", shutdownkey, "ShutdownTime", given_root = key)
        result["key"] = key
        result["hive"] = "SYSTEM"
        result["valuename"] = "ShutdownTime"
        result["value"] = value
        result["timestamp"] = ""
        if value != None:
            try:
                bufferas = addrspace.BufferAddressSpace(self._config, data = value)
                result["timestamp"] = obj.Object("WinTimeStamp", vm = bufferas, offset = 0, is_utc = True)
            except (struct.error, TypeError):
                pass
        yield result

    def unified_output(self, data):
        return TreeGrid([("Registry", str),
                      ("KeyPath", str),
                      ("LastWrite", str),
                      ("ValueName", str),
                      ("Value", str),
                      ], self.generator(data))

    def generator(self, data):
        for result in data:
            if result["key"]:
                yield (0, [str(result["hive"]),
                    str(self.regapi.reg_get_key_path(result["key"])),
                    str(result["key"].LastWriteTime),
                    str(result["valuename"]),
                    str(result["timestamp"] if result["timestamp"] else result["value"])
                ])

    def render_text(self, outfd, data):
        keyfound = False
        for result in data:
            if result["key"]:
                keyfound = True
                outfd.write("Registry: {0}\n".format(result["hive"]))
                outfd.write("Key Path: {0}\n".format(self.regapi.reg_get_key_path(result["key"])))
                outfd.write("Key Last updated: {0}\n".format(result["key"].LastWriteTime))
                outfd.write("Value Name: {0}\n".format(result["valuename"]))
                outfd.write("Value: {0}\n\n".format(result["timestamp"] if result["timestamp"] else result["value"]))        
        if not keyfound:
            outfd.write("The requested key could not be found in the hive(s) searched\n")
