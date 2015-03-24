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


class mac_print_boot_cmdline(common.AbstractMacCommand):
    """ Prints kernel boot arguments """

    def calculate(self):
        common.set_plugin_members(self)

        pe_state_addr = self.addr_space.profile.get_symbol("_PE_state")
        pe_state = obj.Object("PE_state", offset = pe_state_addr, vm = self.addr_space)
        bootargs = pe_state.bootArgs.dereference_as("boot_args")      
 
        yield bootargs.CommandLine
 
    def unified_output(self, data):
        return TreeGrid([("Command Line", str),
                         ], self.generator(data))

    def generator(self, data):
        for cmdline in data:
            yield(0, [str(cmdline),])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Command Line", "")])
        for cmdline in data:
            self.table_row(outfd, cmdline)
