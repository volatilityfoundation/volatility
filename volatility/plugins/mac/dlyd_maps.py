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

class mac_dyld_maps(pstasks.mac_tasks):
    """ Gets memory maps of processes from dyld data structures """

    def unified_output(self, data):
        common.set_plugin_members(self)
        
        return TreeGrid([("Pid", int),
                          ("Name", str),
                          ("Start", str),
                          ("Map Name", str),
                          ], self.generator(data))

    def generator(self, data):
        for proc in data:
            for map in proc.get_dyld_maps():
                yield(0, [
                        int(proc.p_pid),
                        str(proc.p_comm),
                        str(map.imageLoadAddress),
                        str(map.imageFilePath),
                        ])
                             


