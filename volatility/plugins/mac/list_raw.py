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

import volatility.plugins.mac.common as mac_common
import volatility.plugins.mac.ifconfig as mac_ifconfig
import volatility.plugins.mac.pstasks as mac_pstasks
import volatility.debug as debug
import volatility.obj as obj
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_list_raw(mac_common.AbstractMacCommand):
    """List applications with promiscuous sockets"""

    def __init__(self, config, *args, **kwargs):
        self.fd_cache = {}
        mac_common.AbstractMacCommand.__init__(self, config, *args, **kwargs)

    def _fill_cache(self):
        for task in mac_pstasks.mac_tasks(self._config).calculate():
            for filp, _, fd in task.lsof():
                if filp.f_fglob.fg_type == 'DTYPE_SOCKET':
                    socket = filp.f_fglob.fg_data.dereference_as("socket").v() 
         
                    self.fd_cache[socket] = [task, fd]
 
    def calculate(self):
        mac_common.set_plugin_members(self)

        list_addr = self.profile.get_symbol("_rawcb_list")

        list_ptr  = obj.Object("rawcb_list_head", offset = list_addr, vm = self.addr_space)

        cur = list_ptr.lh_first

        self._fill_cache()

        while cur.is_valid():
            socket = cur.rcb_socket.v()
      
            if socket in self.fd_cache:
                (task, fd) = self.fd_cache[socket]
                yield (task, fd, socket)

            cur = cur.list.le_next.dereference()

    def unified_output(self, data):
        return TreeGrid([("Process", str),
                                  ("PID", int),
                                  ("File Descriptor", int),
                                  ("Socket", Address),
                                 ], self.generator(data))

    def generator(self, data):
        for (task, fd, socket) in data:
            yield(0, [
                str(task.p_comm),
                int(task.p_pid),
                int(fd),
                Address(socket),
                ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Process", "16"),
                                  ("PID", "6"),
                                  ("File Descriptor", "5"),
                                  ("Socket", "[addrpad]"),
                                 ])

        for (task, fd, socket) in data:
            self.table_row(outfd, task.p_comm, task.p_pid, fd, socket)

