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

import volatility.plugins.freebsd.common as freebsd_common
import volatility.plugins.freebsd.pslist as freebsd_pslist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class freebsd_proc_maps(freebsd_pslist.freebsd_pslist):
    """List processes and virtual memory mappings"""

    def calculate(self):
        freebsd_common.set_plugin_members(self)

        procs = freebsd_pslist.freebsd_pslist.calculate(self)

        for proc in procs:
            for entry in proc.get_proc_maps():
                yield proc, entry

    def unified_output(self, data):
        return TreeGrid([('Pid', int),
                         ('Name', str),
                         ('Start', Address),
                         ('End', Address),
                         ('Perms', str),
                         ('Type', str),
                         ('Path', str)],
                        self.generator(data))

    def generator(self, data):
        for proc, entry in data:

            yield (0, [int(proc.p_pid),
                       str(proc.p_comm),
                       Address(entry.start),
                       Address(entry.end),
                       entry.get_perms(),
                       entry.get_type(),
                       entry.get_path()])
