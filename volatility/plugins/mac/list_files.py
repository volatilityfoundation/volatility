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
import volatility.plugins.mac.mount as mac_mount

class mac_list_files(common.AbstractMacCommand):
    """ Lists files in the file cache """

    def calculate(self):
        common.set_plugin_members(self)

        mounts = mac_mount.mac_mount(self._config).calculate()

        for mount in mounts:
            vnode = mount.mnt_vnodelist.tqh_first

            while vnode:
                path = vnode.full_path()

                yield vnode, path

                vnode = vnode.v_mntvnodes.tqe_next        
 
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"), ("File Path", "")])
        for vnode, path in data:
            self.table_row(outfd, vnode.v(), path)    

