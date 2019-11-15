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
import volatility.plugins.freebsd.common as freebsd_common
from volatility.renderers import TreeGrid

class freebsd_ifconfig(freebsd_common.AbstractFreebsdCommand):
    """Display network interfaces"""

    def __init__(self, config, *args, **kwargs):
        freebsd_common.AbstractFreebsdCommand.__init__(self, config, *args, **kwargs)

    def walk_ifnethead(self, ifnethead):
        if hasattr(ifnethead, 'tqh_first'):
            ifnet = ifnethead.tqh_first
        else:
            ifnet = ifnethead.cstqh_first
        while ifnet.v():
            yield ifnet
            if hasattr(ifnet.if_link, 'tqe_next'):
                ifnet = ifnet.if_link.tqe_next
            else:
                ifnet = ifnet.if_link.cstqe_next

    def calculate(self):
        freebsd_common.set_plugin_members(self)
        if self.addr_space.profile.get_symbol('ifnet'):
            ifnet_addr = self.addr_space.profile.get_symbol('ifnet')
            ifnethead = obj.Object('ifnethead', offset = ifnet_addr, vm = self.addr_space)
            for ifnet in self.walk_ifnethead(ifnethead):
                yield ifnet
        else:
            vnet_head_addr = self.addr_space.profile.get_symbol('vnet_head')
            vnet_head = obj.Object('vnet_list_head', offset = vnet_head_addr, vm = self.addr_space)
            vnet = vnet_head.lh_first
            while vnet.v():
                ifnet_addr = self.addr_space.profile.get_symbol('vnet_entry_ifnet') + vnet.vnet_data_base
                ifnethead = obj.Object('ifnethead', offset = ifnet_addr, vm = self.addr_space)
                for ifnet in self.walk_ifnethead(ifnethead):
                    yield ifnet
                vnet = vnet.vnet_le.le_next

    def unified_output(self, data):
        return TreeGrid([('Driver name', str),
                         ('Interface name', str),
                         ('Addresses', str)],
                        self.generator(data))

    def generator(self, data):
        for ifnet in data:
            if hasattr(ifnet.if_addrhead, 'tqh_first'):
                ifaddr = ifnet.if_addrhead.tqh_first
            else:
                ifaddr = ifnet.if_addrhead.cstqh_first
            addresses = list()
            while ifaddr.v():
                if ifaddr.ifa_addr.sa_family == 2:
                    addresses.append(str(ifaddr.ifa_addr.dereference_as('sockaddr_in').sin_addr.s_addr))
                elif ifaddr.ifa_addr.sa_family == 28:
                    addresses.append(str(ifaddr.ifa_addr.dereference_as('sockaddr_in6').sin6_addr.__u6_addr))
                if hasattr(ifaddr.ifa_link, 'tqe_next'):
                    ifaddr = ifaddr.ifa_link.tqe_next
                else:
                    ifaddr = ifaddr.ifa_link.cstqe_next
            yield (0, [str(ifnet.if_dname.dereference()),
                       str(ifnet.if_xname),
                       ' '.join(addresses)])
