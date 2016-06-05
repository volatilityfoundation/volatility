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

import socket
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsof as linux_lsof
import volatility.plugins.linux.pslist as linux_pslist

class linux_netstat(linux_pslist.linux_pslist):
    """Lists open sockets"""
    
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('IGNORE_UNIX', short_option = 'U', default = None, help = 'ignore unix sockets', action = 'store_true')
    
            # its a socket!
    def render_text(self, outfd, data):
        linux_common.set_plugin_members(self)

        if not self.addr_space.profile.has_type("inet_sock"):
            # ancient (2.6.9) centos kernels do not have inet_sock in debug info
            raise AttributeError, "Given profile does not have inet_sock, please file a bug if the kernel version is > 2.6.11"

        for task in data:
            for ents in task.netstat():
                if ents[0] == socket.AF_INET:
                    (_, proto, saddr, sport, daddr, dport, state) = ents[1]
                    outfd.write("{0:8s} {1:<16}:{2:>5} {3:<16}:{4:>5} {5:<15s} {6:>17s}/{7:<5d}\n".format(proto, saddr, sport, daddr, dport, state, task.comm, task.pid))

                elif ents[0] == 1 and not self._config.IGNORE_UNIX:
                    (name, inum) = ents[1]
                    outfd.write("UNIX {0:<8d} {1:>17s}/{2:<5d} {3:s}\n".format(inum, task.comm, task.pid, name))
        

