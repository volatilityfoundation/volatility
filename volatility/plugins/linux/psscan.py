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
import struct

import volatility.obj as obj
import volatility.utils as utils
import volatility.poolscan as poolscan
import volatility.debug as debug

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as pslist

from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_psscan(pslist.linux_pslist):
    """ Scan physical memory for processes """

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self.wants_physical = True

    def calculate(self):
        linux_common.set_plugin_members(self)
        
        phys_addr_space = utils.load_as(self._config, astype = 'physical')

        if phys_addr_space.profile.metadata.get('memory_model', '32bit') == "32bit":
            fmt  = "<I"
        else:
            fmt  = "<Q"

        needles     = []
        
        for sym in phys_addr_space.profile.get_all_symbol_names("kernel"):
            if sym.find("_sched_class") != -1:
                addr = phys_addr_space.profile.get_symbol(sym)
                needles.append(struct.pack(fmt, addr)) 

        if len(needles) == 0:
            debug.error("Unable to scan for processes. Please file a bug report.")

        back_offset = phys_addr_space.profile.get_obj_offset("task_struct", "sched_class")

        scanner = poolscan.MultiPoolScanner(needles)    

        for _, offset in scanner.scan(phys_addr_space):
            ptask = obj.Object("task_struct", offset = offset - back_offset, vm = phys_addr_space)

            if not ptask.exit_state.v() in [0, 16, 32, 16|32]:
                continue

            if not (0 < ptask.pid < 66000):
                continue

            yield ptask

        











