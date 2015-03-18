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
import volatility.plugins.mac.pstasks as pstasks 
import volatility.plugins.mac.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_dyld_maps(pstasks.mac_tasks):
    """ Gets memory maps of processes from dyld data structures """

    def unified_output(self, data):
        common.set_plugin_members(self)
        
        return TreeGrid([("Pid", int),
                          ("Name", str),
                          ("Start", Address),
                          ("Map Name", str),
                          ], self.generator(data))

    def generator(self, data):
        for proc in data:
            for map in proc.get_dyld_maps():
                yield(0, [
                        int(proc.p_pid),
                        str(proc.p_comm),
                        Address(map.imageLoadAddress),
                        str(map.imageFilePath),
                        ])

    def render_text(self, outfd, data):
        common.set_plugin_members(self)
        self.table_header(outfd, [("Pid", "8"), 
                          ("Name", "20"),
                          ("Start", "#018x"),
                          ("Map Name", "")])

        for proc in data:
            for map in proc.get_dyld_maps():
                self.table_row(outfd, 
                           str(proc.p_pid),
                           proc.p_comm, 
                           map.imageLoadAddress,
                           map.imageFilePath)
