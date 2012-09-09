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
@author:       Joe Sylve
@license:      GNU General Public License 2.0 or later
@contact:      joe.sylve@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.flags as linux_flags
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.mount as linux_mount
import volatility.plugins.linux.pslist as linux_pslist
from volatility.plugins.linux.slab_info import linux_slabinfo

class linux_mount_cache(linux_mount.linux_mount):
    """Gather mounted fs/devices from kmem_cache"""
    
    def __init__(self, config, *args): 
        linux_mount.linux_mount.__init__(self, config, *args)
        self._config.add_option('UNALLOCATED', short_option = 'u', 
                        default = False,
                        help = 'Show unallocated',
                        action = 'store_true') 
                        
    def calculate(self):
        if self.profile.has_type("mount"):
            mnttype = "mount"
            
            for task in linux_pslist.linux_pslist(self._config).calculate():
                if task.pid == 1:
                    ns = task.nsproxy.mnt_ns
                    break
        else:
            mnttype = "vfsmount"
            ns = None
    
        cache = linux_slabinfo(self._config).get_kmem_cache(mnttype, self._config.UNALLOCATED)

        for mnt in cache:
            yield (mnt, ns)

