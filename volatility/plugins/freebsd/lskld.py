# Volatility
# Copyright (C) 2019 Volatility Foundation
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

import volatility.obj as obj
import volatility.plugins.freebsd.common as freebsd_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class freebsd_lskld(freebsd_common.AbstractFreebsdCommand):
    """Dump kernel linker status"""

    def __init__(self, config, *args, **kwargs):
        freebsd_common.AbstractFreebsdCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        freebsd_common.set_plugin_members(self)
        linker_files_addr = self.addr_space.profile.get_symbol('linker_files')
        linker_files = obj.Object('linker_file_head', offset = linker_files_addr, vm = self.addr_space)
        linker_file = linker_files.tqh_first
        while linker_file.v():
            yield linker_file
            linker_file = linker_file.link.tqe_next

    def unified_output(self, data):
        return TreeGrid([('Id', int),
                         ('Refs', int),
                         ('Address', Address),
                         ('Size', int),
                         ('Name', str)],
                        self.generator(data))

    def generator(self, data):
        for linker_file in data:
            yield (0, [int(linker_file.id),
                       int(linker_file.refs),
                       Address(linker_file.address),
                       int(linker_file.m('size')),
                       str(linker_file.pathname.dereference())])
