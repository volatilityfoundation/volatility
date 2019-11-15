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
import volatility.plugins.freebsd.pslist as freebsd_pslist
from volatility.renderers import TreeGrid

class freebsd_pscred(freebsd_pslist.freebsd_pslist):
    """List processes and security credentials"""

    def unified_output(self, data):
        return TreeGrid([('Pid', int),
                         ('Name', str),
                         ('Euid', int),
                         ('Ruid', int),
                         ('Svuid', int),
                         ('Egid', int),
                         ('Rgid', int),
                         ('Svgid', int),
                         ('Umask', str),
                         ('Flags', str),
                         ('Groups', str)],
                        self.generator(data))

    def generator(self, data):
        for proc in data:
            groups = proc.p_ucred.cr_groups.dereference_as('Array', targetType = 'int', count = proc.p_ucred.cr_ngroups)
            yield (0, [int(proc.p_pid),
                       str(proc.p_comm),
                       int(proc.p_ucred.cr_uid),
                       int(proc.p_ucred.cr_ruid),
                       int(proc.p_ucred.cr_svuid),
                       int(groups[0]),
                       int(proc.p_ucred.cr_rgid),
                       int(proc.p_ucred.cr_svgid),
                       '{0:03o}'.format(proc.p_fd.fd_cmask),
                       'C' if (proc.p_ucred.cr_flags & 0x1) else '-',
                       ','.join([str(group) for group in groups])])
