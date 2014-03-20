# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
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

import volatility.plugins.linux.pslist as linux_pslist

class linux_psenv(linux_pslist.linux_pslist):
    '''Gathers processes along with their environment'''

    def render_text(self, outfd, data):
        outfd.write("{0:6s} {1:6s} {2:12s}\n".format("Name", "Pid", "Environment"))
        for task in data:
            outfd.write("{0:17s} {1:6s} {2:s}\n".format(str(task.comm), str(task.pid), task.get_environment()))
