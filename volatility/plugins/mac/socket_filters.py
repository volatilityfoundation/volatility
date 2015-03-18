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
import volatility.plugins.mac.common as common
import volatility.plugins.mac.lsmod as lsmod
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_socket_filters(lsmod.mac_lsmod):
    """ Reports socket filters """

    def calculate(self):
        common.set_plugin_members(self)
        
        # get the symbols need to check for if rootkit or not
        (kernel_symbol_addresses, kmods) = common.get_kernel_addrs(self)

        members = ["sf_unregistered", "sf_attach", "sf_detach", "sf_notify", "sf_getpeername", "sf_getsockname"]
        members = members + ["sf_data_in", "sf_data_out", "sf_connect_in", "sf_connect_out", "sf_bind", "sf_setoption"]
        members = members + ["sf_getoption", "sf_listen", "sf_ioctl"]

        sock_filter_head_addr = self.addr_space.profile.get_symbol("_sock_filter_head")
    
        sock_filter_list = obj.Object("socket_filter_list", offset = sock_filter_head_addr, vm = self.addr_space)

        cur = sock_filter_list.tqh_first

        while cur:
            filter = cur.sf_filter
            filter_name = self.addr_space.read(filter.sf_name, 256)
            idx = filter_name.index("\x00")
            if idx != -1:
                filter_name = filter_name[:idx]
               
            filter_socket = cur.sf_entry_head.sfe_socket.obj_offset

            for member in members:
                ptr = filter.m(member)
                
                if not ptr:
                    continue   
 
                (good, module) = common.is_known_address_name(ptr.v(), kernel_symbol_addresses, kmods) 
    
                yield good, filter, filter_name, filter_socket, member, ptr, module
       
            cur = cur.sf_global_next.tqe_next

    def unified_output(self, data):
        return TreeGrid([("Offset (V)", Address),
                        ("Filter Name", str),
                        ("Filter Member", str),
                        ("Socket (V)", Address),
                        ("Handler", Address),
                        ("Module", str),
                        ("Status", str),
                        ], self.generator(data))

    def generator(self, data):
        for (good, filter, filter_name, filter_socket, member, ptr, module) in data:
            if good == 0:
                status = "UNKNOWN"
            else:
                status = "OK"
            yield(0, [
                Address(filter.obj_offset),
                str(filter_name),
                str(member),
                Address(filter_socket),
                Address(ptr),
                str(module),
                str(status),
                ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"),
                                  ("Filter Name", "50"), 
                                  ("Filter Member", "16"),
                                  ("Socket (V)", "[addrpad]"),
                                  ("Handler", "[addrpad]"), 
                                  ("Module", "30"),
                                  ("Status", "")])

        for (good, filter, filter_name, filter_socket, member, ptr, module) in data:
            status = "OK"
            if good == 0:
                status = "UNKNOWN"
            self.table_row(outfd, filter.obj_offset, filter_name, member, filter_socket, ptr, module, status)
