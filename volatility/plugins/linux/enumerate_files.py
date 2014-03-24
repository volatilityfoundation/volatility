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
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.mount as linux_mount

class linux_enumerate_files(linux_common.AbstractLinuxCommand):
    """Lists files referenced by the filesystem cache"""

    def _walk_sb(self, dentry_param, last_dentry, parent):
        if last_dentry == None or last_dentry != dentry_param.v():
            last_dentry = dentry_param
        else:
            return

        ret = None
        
        for dentry in dentry_param.d_subdirs.list_of_type("dentry", "d_u"):
            if not dentry.d_name.name.is_valid():
                continue

            inode = dentry.d_inode
            name  = dentry.d_name.name.dereference_as("String", length = 255)

            # do not use os.path.join
            # this allows us to have consistent paths from the user
            new_file = parent + "/" + name

            yield new_file

            if inode and inode.is_dir():
                for new_file in self._walk_sb(dentry, last_dentry, new_file):
                    yield new_file

    def _get_sbs(self):
        ret = []
        mnts = linux_mount.linux_mount(self._config).calculate()

        for (sb, _dev_name, path, fstype, _rr, _mnt_string) in linux_mount.linux_mount(self._config).parse_mnt(mnts):
            ret.append((sb, path))

        return ret

    def walk_sbs(self):
        ret = None
        sbs = self._get_sbs()

        for (sb, sb_path) in sbs:
            if sb_path != "/":
                parent = sb_path
            else:
                parent = ""

            rname  = sb.s_root.d_name.name.dereference_as("String", length = 255)
            if rname and len(rname) > 0:
                yield rname

            for file_path in self._walk_sb(sb.s_root, None, parent):
                yield file_path
    
    def calculate(self):
        linux_common.set_plugin_members(self)

        for file_path in self.walk_sbs():
            yield file_path

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Path", "")])
        for path in data:
            self.table_row(outfd, path)
            
