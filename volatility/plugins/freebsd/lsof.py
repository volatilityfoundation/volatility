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

import volatility.plugins.freebsd.common as freebsd_common
import volatility.plugins.freebsd.pslist as freebsd_pslist
import volatility.protos as protos
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class freebsd_lsof(freebsd_pslist.freebsd_pslist):
    """List processes and open files"""

    def calculate(self):
        freebsd_common.set_plugin_members(self)

        procs = freebsd_pslist.freebsd_pslist.calculate(self)

        for proc in procs:
            for f, n in proc.lsof():
                yield proc, f, n

    def unified_output(self, data):
        return TreeGrid([('Pid', int),
                         ('Name', str),
                         ('File number', int),
                         ('File type', str),
                         ('Vnode type', str),
                         ('Socket type', str),
                         ('Address family', str),
                         ('Protocol', str),
                         ('Path', str),
                         ('Device', str)],
                        self.generator(data))

    def generator(self, data):
        for proc, f, n in data:

            yield (0, [int(proc.p_pid),
                       str(proc.p_comm),
                       n,
                       str(f.f_type),
                       str(f.f_vnode.v_type) if str(f.f_type) == 'DTYPE_VNODE' else '',
                       str(f.f_data.dereference_as('socket').so_type) if str(f.f_type) == 'DTYPE_SOCKET' else '',
                       str(f.f_data.dereference_as('socket').so_proto.pr_domain.dom_family) if str(f.f_type) == 'DTYPE_SOCKET' else '',
                       protos.protos.get(f.f_data.dereference_as('socket').so_proto.pr_protocol.v(), 'UNKNOWN') if str(f.f_type) == 'DTYPE_SOCKET' and str(f.f_data.dereference_as('socket').so_proto.pr_domain.dom_family).startswith('AF_INET') else '',
                       f.f_vnode.get_vpath() if str(f.f_type) == 'DTYPE_VNODE' and (str(f.f_vnode.v_type) == 'VDIR' or str(f.f_vnode.v_type) == 'VREG') else '',
                       str(f.f_vnode.v_un.vu_cdev.si_name) if str(f.f_type) == 'DTYPE_VNODE' and (str(f.f_vnode.v_type) == 'VBLK' or str(f.f_vnode.v_type) == 'VCHR') and hasattr(f.f_vnode, 'v_un') else str(f.f_vnode.v_rdev.si_name) if str(f.f_type) == 'DTYPE_VNODE' and (str(f.f_vnode.v_type) == 'VBLK' or str(f.f_vnode.v_type) == 'VCHR') else ''])
