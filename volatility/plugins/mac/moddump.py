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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""
import os
import re
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.mac.common as common

class mac_moddump(common.AbstractMacCommand):
    """ Writes the specified kernel extension to disk """
    
    def __init__(self, config, *args, **kwargs):         
        common.AbstractMacCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('BASE', short_option = 'b', default = None, help = 'Dump driver with BASE address (in hex)', action = 'store', type = 'int')
        self._config.add_option('REGEX', short_option = 'r', help = 'Dump modules matching REGEX', action = 'store', type = 'string')
        self._config.add_option('IGNORE-CASE', short_option = 'i', help = 'Ignore case in pattern match', action = 'store_true', default = False)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

    def calculate(self):
        common.set_plugin_members(self)

        if self._config.REGEX:
            try:
                if self._config.IGNORE_CASE:
                    mod_re = re.compile(self._config.REGEX, re.I)
                else:
                    mod_re = re.compile(self._config.REGEX)
            except re.error, e:
                debug.error('Error parsing regular expression: {0}'.format(e))
                
        if self._config.BASE:
            module_address = int(self._config.BASE)
            yield obj.Object("kmod_info", offset = module_address, vm = self.addr_space)
        else:
            modules_addr = self.addr_space.profile.get_symbol("_kmod")
            modules_ptr = obj.Object("Pointer", vm = self.addr_space, offset = modules_addr)
            mod = modules_ptr.dereference_as("kmod_info")

            while mod.is_valid():
                if self._config.REGEX and not mod_re.search(str(mod.name)):
                    mod = mod.next
                    continue
                
                yield mod
  
                mod = mod.next

    def render_text(self, outfd, data):
        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")
 
        self.table_header(outfd, [("Address", "[addrpad]"), 
                                  ("Size", "8"), 
                                  ("Output Path", "")])
        for kmod in data:
            start = kmod.address
            size  = kmod.m("size")

            file_name = "{0}.{1:#x}.kext".format(kmod.name, kmod.obj_offset)
            mod_file = open(os.path.join(self._config.DUMP_DIR, file_name), 'wb')
            mod_data = self.addr_space.read(kmod.address, size)
            mod_file.write(mod_data)
            mod_file.close()
            self.table_row(outfd, start, size, file_name)



