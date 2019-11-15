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
import volatility.utils as utils
import volatility.plugins.freebsd.common as freebsd_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class freebsd_pslist(freebsd_common.AbstractFreebsdCommand):
    """List processes"""

    def __init__(self, config, *args, **kwargs):
        freebsd_common.AbstractFreebsdCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')

    @staticmethod
    def virtual_process_from_physical_offset(addr_space, offset):
        pspace = utils.load_as(addr_space.get_config(), astype = 'physical')
        proc = obj.Object('proc', vm = pspace, offset = offset)
        thread = obj.Object('thread', vm = addr_space, offset = proc.p_threads.tqh_first)

        return thread.td_proc

    def calculate(self):
        freebsd_common.set_plugin_members(self)

        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]

        addr = self.addr_space.profile.get_symbol('allproc')
        allproc = obj.Object('proclist', offset = addr, vm = self.addr_space)
        proc = allproc.lh_first
        while proc.v():
            if not pidlist or proc.p_pid in pidlist:
                yield proc
            proc = proc.p_list.le_next

        addr = self.addr_space.profile.get_symbol('zombproc')
        zombproc = obj.Object('proclist', offset = addr, vm = self.addr_space)
        proc = zombproc.lh_first
        while proc.v():
            if not pidlist or proc.p_pid in pidlist:
                yield proc
            proc = proc.p_list.le_next

    def unified_output(self, data):
        return TreeGrid([('Offset (V)', Address),
                         ('Pid', int),
                         ('Name', str)],
                        self.generator(data))

    def generator(self, data):
        for proc in data:
            yield (0, [Address(proc.v()),
                       int(proc.p_pid),
                       str(proc.p_comm)])
