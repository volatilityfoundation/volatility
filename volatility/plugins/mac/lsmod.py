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

import volatility.obj as obj
import volatility.plugins.mac.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_lsmod(common.AbstractMacCommand):
    """ Lists loaded kernel modules """

    def __init__(self, config, *args, **kwargs):
        common.AbstractMacCommand.__init__(self, config, *args, **kwargs)
        
        config.add_option('ADDR', short_option = 'a', default = None, help = 'Show info on VAD at or containing this address', action = 'store', type = 'int')

    def calculate(self):
        common.set_plugin_members(self)

        p = self.addr_space.profile.get_symbol("_kmod")
        kmodaddr = obj.Object("Pointer", offset = p, vm = self.addr_space)
        kmod = kmodaddr.dereference_as("kmod_info") 

        while kmod.is_valid():
            if not self._config.ADDR or (kmod.address <= self._config.ADDR <= (kmod.address + kmod.m("size"))):
                yield kmod
            kmod = kmod.next

    def unified_output(self, data):
        return TreeGrid([("Offset (V)", Address),
                        ("Module Address", Address),
                        ("Size", int),
                        ("Refs", int),
                        ("Version", str),
                        ("Name", str),
                        ], self.generator(data))
    def generator(self, data):
        for kmod in data:
            yield (0, [
                    Address(kmod.obj_offset),
                    Address(kmod.address),
                    int(kmod.m('size')),
                    int(kmod.reference_count),
                    str(kmod.version),
                    str(kmod.name),
                    ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"),
                                  ("Module Address", "[addrpad]"), 
                                  ("Size", "8"), 
                                  ("Refs", "^8"),
                                  ("Version", "12"),  
                                  ("Name", "")])
        for kmod in data:
            self.table_row(outfd,
                           kmod, 
                           kmod.address, 
                           kmod.m('size'), 
                           kmod.reference_count, 
                           kmod.version, 
                           kmod.name)
