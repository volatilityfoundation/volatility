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

    def calculate(self):
        linux_common.set_plugin_members(self)
        mntptr = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("mount_hashtable"), vm = self.addr_space)

        mnt_list = obj.Object(theType = "Array", offset = mntptr.v(), vm = self.addr_space, targetType = "list_head", count = 512)

        if self.profile.has_type("mount"):
            mnttype = "mount"

            for task in linux_pslist.linux_pslist(self._config).calculate():
                if task.pid == 1:
                    ns = task.nsproxy.mnt_ns
                    break

        else:
            mnttype = "vfsmount"
            ns = None

        # get each list_head out of the array
        for outerlist in mnt_list:

            for mnt in outerlist.list_of_type(mnttype, "mnt_hash"):
                yield (mnt, ns)

    def parse_mnt(self, data):
        '''
        We use seen for 3.x kernels with mount namespaces 
        The same mount can be in multiple namespaces and we do not want to repeat output
        '''
        for (mnt, ns) in data:

            dev_name = mnt.mnt_devname.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)

            if not dev_name.is_valid() or len(dev_name) == 0:
                continue

            fstype = mnt.mnt_sb.s_type.name.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)

            if not fstype.is_valid() or len(fstype) == 0:
                continue

            path = linux_common.do_get_path(mnt.mnt_sb.s_root, mnt.mnt_parent, mnt.mnt_root, mnt)

            if path == []:
                continue

            mnt_string = self.calc_mnt_string(mnt)

            if (mnt.mnt_flags & 0x40) or (mnt.mnt_sb.s_flags & 0x1):
                rr = "ro"
            else:
                rr = "rw"

            if not ns or ns == mnt.mnt_ns:
                yield mnt.mnt_sb, dev_name, path, fstype, rr, mnt_string

    def render_text(self, outfd, data):
        data = self.parse_mnt(data)

        for (_sb, dev_name, path, fstype, rr, mnt_string) in data:
            outfd.write("{0:25s} {1:35s} {2:12s} {3:2s}{4:64s}\n".format(dev_name, path, fstype, rr, mnt_string))

    def calc_mnt_string(self, mnt):

        ret = ""

        for mflag in linux_flags.mnt_flags:
            if mflag & mnt.mnt_flags:
                ret = ret + linux_flags.mnt_flags[mflag]

        return ret

