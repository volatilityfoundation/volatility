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
        ret = None

        if not mnt.mnt_root.is_valid():
            return ret

        dev_name = mnt.mnt_devname.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)
        if not dev_name.is_valid():
            return ret

        fstype = mnt.mnt_sb.s_type.name.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)

        if not fstype.is_valid():
            return ret

        #print fs_types
        #if str(fstype) not in fs_types:
        #    return ret

        path = linux_common.do_get_path(mnt.mnt_sb.s_root, mnt.mnt_parent, mnt.mnt_root, mnt)

        if path == []:
            return ret

        mnt_string = self._calc_mnt_string(mnt)

        if (mnt.mnt_flags & 0x40) or (mnt.mnt_sb.s_flags & 0x1):
            rr = "ro"
        else:
            rr = "rw"
        
        return mnt.mnt_sb, str(dev_name), path, fstype, rr, mnt_string

    def calculate(self):
        linux_common.set_plugin_members(self)
        mntptr   = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("mount_hashtable"), vm = self.addr_space)
        mnt_list = obj.Object(theType = "Array", offset = mntptr, vm = self.addr_space, targetType = "list_head", count = 8200)

        if self.profile.has_type("mount"):
            mnttype = "mount"
        else:
            mnttype = "vfsmount"

        ns = None        
        fs_types = self._get_filesystem_types()

        hash_mnts = {}
        seen_outer = {}
        for (idx, outerlist) in enumerate(mnt_list):
            if outerlist == None or outerlist.next == None:
                continue

            if outerlist.next.v() in seen_outer:
                continue

            seen_outer[outerlist.next.v()] = 1

            if outerlist == outerlist.next or not outerlist.m("next").is_valid():
                continue

            seen = {}
            for mnt in outerlist.list_of_type(mnttype, "mnt_hash"):
                if mnt.v() in seen:
                    break

                seen[mnt.v()] = 1

                if len(seen.keys()) > 1024:
                    break

                if mnt.is_valid():
                    hash_mnts[mnt]            = 1
                else:
                    break

                if mnt.mnt_parent.is_valid():
                    hash_mnts[mnt.mnt_parent] = 1
    
                if mnt.mnt_parent.mnt_parent.is_valid():    
                    hash_mnts[mnt.mnt_parent.mnt_parent] = 1

        child_mnts = {}
        for mnt in hash_mnts:
            cseen = {}
            for child_mnt in mnt.mnt_child.list_of_type(mnttype, "mnt_child"):
                if not child_mnt.is_valid():
                    break
                
                child_mnts[child_mnt]            = 1
  
                if child_mnt.v() in cseen:
                    break

                cseen[child_mnt.v()] = 1
  
                if child_mnt.mnt_parent.is_valid():
                    child_mnts[child_mnt.mnt_parent] = 1
                
                if child_mnt.mnt_parent.mnt_parent.is_valid():
                    child_mnts[child_mnt.mnt_parent.mnt_parent] = 1

        tmp_mnts = list(set(hash_mnts.keys() + child_mnts.keys()))
        all_mnts = []

        for t in tmp_mnts:
            tt = t.mnt_devname.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)
            if tt:
                tmp = str(tt)
                if len(str(tmp)) > 2 and (str(tmp)[0] == '/' or tmp in ['devtmpfs', 'proc', 'sysfs', 'nfsd', 'tmpfs', 'sunrpc', 'devpts', 'none']):
                    all_mnts.append(t)

        list_mnts    = {} 
        seen_m       = {}
        for mnt in all_mnts:
            if mnt.v() in seen_m:
                continue
            else:
                seen_m[mnt.v()] = 1 

            for (idx, child_mnt) in enumerate(mnt.mnt_list.list_of_type(mnttype, "mnt_list")):
                if idx > 20:
                    break

                if child_mnt.is_valid():
                    list_mnts[child_mnt]            = 1
                
                if child_mnt.mnt_parent.is_valid():
                    list_mnts[child_mnt.mnt_parent] = 1
                
                if child_mnt.mnt_parent.mnt_parent.is_valid():
                    list_mnts[child_mnt.mnt_parent.mnt_parent] = 1

        all_mnts = list(set(all_mnts + list_mnts.keys()))

        seen = {}
        for (idx, mnt) in enumerate(all_mnts):
            if mnt.mnt_sb.v() not in seen:
                ret = self._parse_mnt(mnt, ns, fs_types)
                        
                mark = False
                
                if ret:
                    (mnt_sb, dev_name, path, fstype, rr, mnt_string) = ret

                    if not (dev_name == "devtmpfs" and path == "/"):
                        yield (mnt_sb, dev_name, path, fstype, rr, mnt_string)
                        mark = True

                if mark:
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


