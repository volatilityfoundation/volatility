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
import volatility.plugins.linux.flags as linux_flags
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_mount(linux_common.AbstractLinuxCommand):
    """Gather mounted fs/devices"""

    def _parse_mnt(self, mnt, ns, fs_types):
        dev_name = mnt.mnt_devname.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)
        
        #if not dev_name.is_valid() or len(dev_name) < 2:
        #    return

        fstype = mnt.mnt_sb.s_type.name.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)

        if not fstype.is_valid():
            return 

        if str(fstype) not in fs_types:
            return 

        path = linux_common.do_get_path(mnt.mnt_sb.s_root, mnt.mnt_parent, mnt.mnt_root, mnt)

        if path == []:
            return

        mnt_string = self._calc_mnt_string(mnt)

        if (mnt.mnt_flags & 0x40) or (mnt.mnt_sb.s_flags & 0x1):
            rr = "ro"
        else:
            rr = "rw"
        
        yield mnt.mnt_sb, dev_name, path, fstype, rr, mnt_string

    def calculate(self):
        linux_common.set_plugin_members(self)
        mntptr   = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("mount_hashtable"), vm = self.addr_space)
        mnt_list = obj.Object(theType = "Array", offset = mntptr, vm = self.addr_space, targetType = "list_head", count = 4099)

        if self.profile.has_type("mount"):
            mnttype = "mount"
        else:
            mnttype = "vfsmount"

        ns = None        
        fs_types = self._get_filesystem_types()
        seen = {}

        all_mnts = []

        for outerlist in mnt_list:
            if outerlist == outerlist.next:
                continue

            for mnt in outerlist.list_of_type(mnttype, "mnt_hash"):
                all_mnts.append(mnt)
                all_mnts.append(mnt.mnt_parent)

        tmp_mnts = []
        for mnt in all_mnts:
            for child_mnt in mnt.mnt_child.list_of_type(mnttype, "mnt_child"):
                tmp_mnts.append(child_mnt)
                tmp_mnts.append(child_mnt.mnt_parent)
    
        all_mnts = all_mnts + tmp_mnts
   
        tmp_mnts = []
        for mnt in all_mnts:
            for child_mnt in mnt.mnt_list.list_of_type(mnttype, "mnt_list"):
                tmp_mnts.append(child_mnt)
                tmp_mnts.append(child_mnt.mnt_parent)
       
        all_mnts = all_mnts + tmp_mnts   

        for mnt in all_mnts:
            if mnt.mnt_sb.v() not in seen:
                for (mnt_sb, dev_name, path, fstype, rr, mnt_string) in self._parse_mnt(mnt, ns, fs_types):
                    yield (mnt_sb, dev_name, path, fstype, rr, mnt_string)
            
            seen[mnt.mnt_sb.v()] = 1

    def _calc_mnt_string(self, mnt):
        ret = ""

        for mflag in linux_flags.mnt_flags:
            if mflag & mnt.mnt_flags:
                ret = ret + linux_flags.mnt_flags[mflag]

        return ret

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

    def render_text(self, outfd, data):
        for (_sb, dev_name, path, fstype, rr, mnt_string) in data:
            outfd.write("{0:25s} {1:35s} {2:12s} {3:2s}{4:64s}\n".format(dev_name, path, fstype, rr, mnt_string))


