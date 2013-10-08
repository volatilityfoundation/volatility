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

import volatility.plugins.linux.common as linux_common
from volatility.plugins.linux.slab_info import linux_slabinfo

class linux_dentry_cache(linux_common.AbstractLinuxCommand):
    """Gather files from the dentry cache"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('UNALLOCATED', short_option = 'u',
                        default = False,
                        help = 'Show unallocated',
                        action = 'store_true')

    def make_body(self, dentry):
        """Create a pipe-delimited bodyfile from a dentry structure. 
        
        MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
        """
        
        path = dentry.get_partial_path() or ""
        i = dentry.d_inode
        
        if i:
            ret = [0, path, i.i_ino, 0, i.i_uid, i.i_gid, i.i_size, i.i_atime, i.i_mtime, 0, i.i_ctime]
        else:
            ret = [0, path] + [0] * 8
            
        ret = "|".join([str(val) for val in ret])
        return ret

    def calculate(self):
        linux_common.set_plugin_members(self)

        cache = linux_slabinfo(self._config).get_kmem_cache("dentry", self._config.UNALLOCATED)

        # support for old kernels 
        if cache == []:
            cache = linux_slabinfo(self._config).get_kmem_cache("dentry_cache", self._config.UNALLOCATED, struct_name = "dentry")

        for dentry in cache:
            yield self.make_body(dentry)

    def render_text(self, outfd, data):

        for bodyline in data:
            outfd.write(bodyline + "\n")



