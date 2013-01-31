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

class mac_lsmod(common.AbstractMacCommand):
    """ Lists loaded kernel modules """

    def calculate(self):
        common.set_plugin_members(self)

        p = self.get_profile_symbol("_kmod")
        kmodaddr = obj.Object("Pointer", offset = p, vm = self.addr_space)
        kmod = kmodaddr.dereference_as("kmod_info") 

        while kmod.is_valid():
            yield kmod
            kmod = kmod.next

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Address", "[addrpad]"), 
                                  ("Size", "[addr]"), 
                                  ("Refs", "8"),
                                  ("Version", "12"),  
                                  ("Name", "")])
        for kmod in data:
            self.table_row(outfd, 
                           kmod.address, 
                           kmod.m('size'), 
                           kmod.reference_count, 
                           kmod.version, 
                           kmod.name)
