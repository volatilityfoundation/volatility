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
    
    def calculate(self):
        linux_common.set_plugin_members(self)
        if not self.profile.has_type("inet_sock"):
            # ancient (2.6.9) centos kernels do not have inet_sock in debug info
            raise AttributeError, "Given profile does not have inet_sock, please file a bug if the kernel version is > 2.6.11"

        openfiles = linux_lsof.linux_lsof(self._config).calculate()

        for (task, filp, i) in openfiles:

            # its a socket!
            if filp.f_op == self.addr_space.profile.get_symbol("socket_file_ops") or filp.dentry.d_op == self.addr_space.profile.get_symbol("sockfs_dentry_operations"):

                iaddr = filp.dentry.d_inode
                skt = self.SOCKET_I(iaddr)
                inet_sock = obj.Object("inet_sock", offset = skt.sk, vm = self.addr_space)

                yield task, i, inet_sock

    def render_text(self, outfd, data):

        for task, _fd, inet_sock in data:

            if inet_sock.protocol in ("TCP", "UDP", "IP", "HOPOPT"): #hopopt is where unix sockets end up on linux

                state = inet_sock.state if inet_sock.protocol == "TCP" else ""
                family = inet_sock.sk.__sk_common.skc_family #pylint: disable-msg=W0212

                if family == socket.AF_UNIX:

                    # the user choose to ignore unix sockets
                    if self._config.IGNORE_UNIX:
                        continue

                    unix_sock = obj.Object("unix_sock", offset = inet_sock.sk.v(), vm = self.addr_space)

                    if unix_sock.addr:

                        name = obj.Object("sockaddr_un", offset = unix_sock.addr.name.obj_offset, vm = self.addr_space)

                        # only print out sockets with paths
                        if str(name.sun_path) != "":
                            outfd.write("UNIX {0:s}\n".format(name.sun_path))

                elif family in (socket.AF_INET, socket.AF_INET6):

                    sport = inet_sock.src_port 
                    dport = inet_sock.dst_port 
                    saddr = inet_sock.src_addr
                    daddr = inet_sock.dst_addr

                    outfd.write("{0:8s} {1}:{2:<5} {3}:{4:<5} {5:s} {6:>17s}/{7:<5d}\n".format(inet_sock.protocol, saddr, sport, daddr, dport, state, task.comm, task.pid))

                #else:
                #    print "unknown family: %d" % family

    # has to get the struct socket given an inode (see SOCKET_I in sock.h)
    def SOCKET_I(self, inode):
        # if too many of these, write a container_of
        backsize = self.profile.get_obj_size("socket")
        addr = inode - backsize

        return obj.Object('socket', offset = addr, vm = self.addr_space)
