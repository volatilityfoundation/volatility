# Volatility
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
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.mount as linux_mount
import volatility.plugins.linux.pslist as linux_pslist
from volatility.plugins.linux.slab_info import linux_slabinfo

class linux_mount_cache(linux_mount.linux_mount):
    """Gather mounted fs/devices from kmem_cache"""

    def __init__(self, config, *args, **kwargs):
        linux_mount.linux_mount.__init__(self, config, *args, **kwargs)
        self._config.add_option('UNALLOCATED', short_option = 'u',
                        default = False,
                        help = 'Show unallocated',
                        action = 'store_true')

    def calculate(self):
        linux_common.set_plugin_members(self)
    
        # newer kernels
        if self.profile.has_type("mount"):
            mnttype = "mount"
        
            cache = linux_slabinfo(self._config).get_kmem_cache(mnttype, self._config.UNALLOCATED)

            for task in linux_pslist.linux_pslist(self._config).calculate():
                if task.pid == 1:
                    ns = task.nsproxy.mnt_ns
                    break
        else:
            cache = linux_slabinfo(self._config).get_kmem_cache("mnt_cache", self._config.UNALLOCATED, struct_name = "vfsmount")
            ns = None

        for mnt in cache:
            yield (mnt, ns)

