# Volatility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import common

class mac_mount(common.AbstractMacCommand):
    """ Prints mounted device information """

    def calculate(self):
        common.set_plugin_members(self)

        mountlist_addr = self.get_profile_symbol("_mountlist")

        mount = obj.Object("mount", offset=mountlist_addr, vm=self.addr_space)

        while mount:
            mnttype  = common.get_string(mount.mnt_vfsstat.f_fstypename.obj_offset, self.addr_space, 16)
            dev      = common.get_string(mount.mnt_vfsstat.f_mntonname.obj_offset,  self.addr_space, 1024) 
            mntpoint = common.get_string(mount.mnt_vfsstat.f_mntfromname.obj_offset, self.addr_space, 1024)

            yield (mnttype, dev, mntpoint)

            mount = mount.mnt_list.tqe_next
        
    def render_text(self, outfd, data):
        for (mnttype, dev, mntpoint) in data:
            outfd.write("{0:32s} {1:32} {2:32}\n".format(dev, mntpoint, mnttype))

