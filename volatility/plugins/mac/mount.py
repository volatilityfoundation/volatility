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

import volatility.obj as obj
import volatility.plugins.mac.common as common

class mac_mount(common.AbstractMacCommand):
    """ Prints mounted device information """

    def calculate(self):
        common.set_plugin_members(self)

        mountlist_addr = self.addr_space.profile.get_symbol("_mountlist")
        mount = obj.Object("mount", offset = mountlist_addr, vm = self.addr_space)
        mount = mount.mnt_list.tqe_next

        while mount:
            yield mount
            mount = mount.mnt_list.tqe_next
        
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Device", "30"), ("Mount Point", "60"), ("Type", "")])
        for mount in data:
            self.table_row(outfd, 
                           mount.mnt_vfsstat.f_mntonname, 
                           mount.mnt_vfsstat.f_mntfromname, 
                           mount.mnt_vfsstat.f_fstypename)
