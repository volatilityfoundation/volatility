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
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import volatility.plugins.linux.flags as linux_flags
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_proc_maps(linux_pslist.linux_pslist):
    """Gathers process maps for linux"""

    MINORBITS = 20
    MINORMASK = ((1 << MINORBITS) - 1)

    def mask_number(self, number):

        if self.profile.get_obj_size("address") == 4:
            mask = 0xffffffff
        else:
            mask = 0xffffffffffffffff

        return number & mask

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            if task.mm:
                for vma in linux_common.walk_internal_list("vm_area_struct", "vm_next", task.mm.mmap):
                    yield task, vma

    def render_text(self, outfd, data):
        for task, vma in data:

            mm = task.mm

            if vma.vm_file:
                inode = vma.vm_file.dentry.d_inode
                sb = obj.Object("super_block", offset = inode.i_sb, vm = self.addr_space)
                dev = sb.s_dev
                ino = inode.i_ino
                pgoff = vma.vm_pgoff << 12 # FIXME: 64-bit support
                fname = linux_common.get_path(task, vma.vm_file)
            else:
                (dev, ino, pgoff) = [0] * 3

                if vma.vm_start <= mm.start_brk and vma.vm_end >= mm.brk:
                    fname = "[heap]"

                elif vma.vm_start <= mm.start_stack and vma.vm_end >= mm.start_stack:
                    fname = "[stack]"

                else:
                    fname = ""

            outfd.write("{0:#8x}-{1:#8x} {2:3} {3:10d} {4:#2d}:{5:#2d} {6:#12d} {7}\n".format(
                    self.mask_number(vma.vm_start),
                    self.mask_number(vma.vm_end),
                    self.format_perms(vma.vm_flags),
                    pgoff,
                    self.MAJOR(dev),
                    self.MINOR(dev),
                    ino,
                    fname))

    def format_perms(self, vma_flags):

        ret = ""
        check = [linux_flags.VM_READ, linux_flags.VM_WRITE, linux_flags.VM_EXEC]
        perms = "rwx"

        for idx in range(len(check)):
            if vma_flags & check[idx]:
                ret = ret + perms[idx]
            else:
                ret = ret + "-"
        return ret

    def MAJOR(self, num):
        return num >> self.MINORBITS

    def MINOR(self, num):
        return num & self.MINORMASK
