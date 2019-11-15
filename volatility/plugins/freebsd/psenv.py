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

import volatility.plugins.freebsd.pslist as freebsd_pslist
from volatility.renderers import TreeGrid

class freebsd_psenv(freebsd_pslist.freebsd_pslist):
    """List processes and environment variables"""

    def unified_output(self, data):
        return TreeGrid([('Pid', int),
                         ('Name', str),
                         ('Environment', str)],
                        self.generator(data))

    def generator(self, data):
        for proc in data:
            yield (0, [int(proc.p_pid),
                       str(proc.p_comm),
                       proc.get_environment()])
