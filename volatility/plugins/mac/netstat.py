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
import volatility.plugins.mac.pstasks as mac_tasks
from volatility.renderers import TreeGrid

class mac_netstat(mac_tasks.mac_tasks):
    """ Lists active per-process network connections """

    def unified_output(self, data):
        return TreeGrid([("Proto", str),
                         ("Local IP", str),
                         ("Local Port", str),
                         ("Remote IP", str),
                         ("Remote Port", str),
                         ("State", str),
                         ("Process", str),
                         ("PID", str)
                         ], 
                         self.generator(data))
                         
    def generator(self, data):
        for proc in data:
            for (family, info) in proc.netstat():
                if family == 1:
                    (socket, path) = info
                    if path:
                    	yield(0, [
                                "UNIX", 
                                str(path).strip(), 
                                "-", 
                                "-", 
                                "-", 
                                "-", 
                                "-",
                                "-",
                                ])
                    			
                elif family in [2, 30]:
                    (socket, proto, lip, lport, rip, rport, state) = info
                    yield(0, [
                            str(proto), 
                            str(lip), 
                            str(lport), 
                            str(rip), 
                            str(rport), 
                            str(state), 
                            str(proc.p_comm),
                            str(proc.p_pid),
                            ])
                    
