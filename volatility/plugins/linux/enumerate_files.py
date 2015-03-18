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
import volatility.plugins.linux.find_file  as linux_find_file
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_enumerate_files(linux_common.AbstractLinuxCommand):
    """Lists files referenced by the filesystem cache"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        for (_, _, file_path, file_dentry)in linux_find_file.linux_find_file(self._config).walk_sbs():
            inode = file_dentry.d_inode

            yield inode, inode.i_ino, file_path

    def unified_output(self, data):
        return TreeGrid([("Inode Number", int), ("Inode", Address), ("Path", str)],
                        self.generator(data))

    def generator(self, data):
        for inode, inum, path in data:
            yield (0, [int(inum), Address(inode.v()), str(path)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Inode Number", "25"), ("Inode", "[addr]"), ("Path", "")])
        for inode, inum, path in data:
            self.table_row(outfd, inode, inum, path) 
