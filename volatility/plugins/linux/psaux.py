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

import volatility.plugins.linux.pslist as linux_pslist

class linux_psaux(linux_pslist.linux_pslist):
    '''Gathers processes along with full command line and start time'''

    def render_text(self, outfd, data):

        outfd.write("{1:6s} {2:6s} {3:6s} {0:64s}\n".format("Arguments", "Pid", "Uid", "Gid"))

        for task in data:
            outfd.write("{1:6s} {2:6s} {3:6s} {0:64s}\n".format(task.get_commandline(), str(task.pid), str(task.uid), str(task.gid)))
