# Volatility
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.plugins.mac.common as common

class mac_print_boot_cmdline(common.AbstractMacCommand):
    """ Prints kernel boot arguments """

    def calculate(self):
        common.set_plugin_members(self)

        pe_state_addr = self.get_profile_symbol("_PE_state")
        pe_state = obj.Object("PE_state", offset = pe_state_addr, vm = self.addr_space)
        bootargs = pe_state.bootArgs.dereference_as("boot_args")      
 
        yield bootargs.CommandLine
 
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Command Line", "")])
        for cmdline in data:
            self.table_row(outfd, cmdline)
