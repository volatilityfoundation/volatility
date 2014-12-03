# Volatility
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
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
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

    def _get_filesystem_types(self):
        all_fs = {}
        
        fs_ptr = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("file_systems"), vm = self.addr_space)
        file_systems = fs_ptr.dereference_as("file_system_type")

        fs = file_systems

        while fs.is_valid():
            fsname = obj.Object("String", offset = fs.name, vm = self.addr_space, length=256)
            all_fs[str(fsname)] = fs
            fs = fs.next

        return all_fs

    def calculate(self):
        linux_common.set_plugin_members(self)
        
        fs_types = self._get_filesystem_types()
    
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
            ret = self._parse_mnt(mnt, ns, fs_types)
                    
            if ret:
                (mnt_sb, dev_name, path, fstype, rr, mnt_string) = ret

                if not (dev_name == "devtmpfs" and path == "/"):
                    yield (mnt_sb, dev_name, path, fstype, rr, mnt_string)

