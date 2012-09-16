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
import volatility.plugins.linux.common as linux_common
from volatility.plugins.linux.slab_info import linux_slabinfo

class linux_dentry_cache(linux_common.AbstractLinuxCommand):
    """Gather files from the dentry cache"""
    
    def __init__(self, config, *args): 
        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('UNALLOCATED', short_option = 'u', 
                        default = False,
                        help = 'Show unallocated',
                        action = 'store_true')       
    
    def make_body(self, path, dentry):
        i = dentry.d_inode

        # MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
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
            cache = linux_slabinfo(self._config).get_kmem_cache("dentry_cache", self._config.UNALLOCATED, struct_name="dentry") 
     
        for dentry in cache:
            path     = linux_common.get_partial_path(dentry)
            bodyline = self.make_body(path, dentry)

            yield bodyline

    def render_text(self, outfd, data):

        for bodyline in data:
            outfd.write(bodyline + "\n")


 
