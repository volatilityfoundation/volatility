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
import volatility.utils as utils
import volatility.plugins.freebsd.common as freebsd_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import socket

class freebsd_tcpconns(freebsd_common.AbstractFreebsdCommand):
    """List TCP connections"""

    def __init__(self, config, *args, **kwargs):
        freebsd_common.AbstractFreebsdCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        freebsd_common.set_plugin_members(self)


        tcbinfo_addr = self.addr_space.profile.get_symbol('tcbinfo')
        if not tcbinfo_addr:
            raise RuntimeError("Unsupported version: don't know where to find the list of connections")

        info = obj.Object('inpcbinfo', offset = tcbinfo_addr, vm = self.addr_space)
        c = info.ipi_listhead.dereference().lh_first.dereference().cast("inpcb")
        while c.v():
            endpoints = c.inp_inc.inc_ie
            local_ip    = endpoints.ie_dependladdr.ie46_local.ia46_addr4.s_addr
            remote_ip   = endpoints.ie_dependfaddr.ie46_foreign.ia46_addr4.s_addr
            local_port  = endpoints.ie_lport
            remote_port = endpoints.ie_fport

            # TCP state should be accessible through c.inp_ppcb.cast("tcpcb").t_state
            # but the module.c did not include its definition so we
            # don't know how to access it

            c = c.inp_list.le_next
            yield (local_ip, remote_ip, socket.htons(local_port), socket.htons(remote_port))

    def unified_output(self, data):
        return TreeGrid([
                ('Local IP', str),
                ('Remote IP', str),
                ('Local port', int),
                ('Remote port', int),

                ], self.generator(data))

    def generator(self, data):
        for (lip, rip, lp, rp) in data:
            yield (0, [str(lip), str(rip), int(lp), int(rp)])
