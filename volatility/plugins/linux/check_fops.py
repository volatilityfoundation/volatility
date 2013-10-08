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

import os
import volatility.obj as obj
import volatility.debug as debug

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsof as linux_lsof
import volatility.plugins.linux.lsmod as linux_lsmod
from volatility.plugins.linux.slab_info import linux_slabinfo

class linux_check_fop(linux_common.AbstractLinuxCommand):
    """Check file operation structures for rootkit modifications"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('INODE', short_option = 'i', default = None, help = 'inode to check', action = 'store', type='int')

    def check_open_files_fop(self, f_op_members, modules):
        # get all the members in file_operations, they are all function pointers
        openfiles = linux_lsof.linux_lsof(self._config).calculate()

        for (task, filp, i) in openfiles:
            for (hooked_member, hook_address) in self.verify_ops(filp.f_op, f_op_members, modules):
                name = "{0:s} {1:d} {2:s}".format(task.comm, i, linux_common.get_path(task, filp))
                yield (name, hooked_member, hook_address)

    def check_proc_fop(self, f_op_members, modules):

        proc_mnt_addr = self.addr_space.profile.get_symbol("proc_mnt")
        if not proc_mnt_addr:
            return

        proc_mnt_ptr = obj.Object("Pointer", offset = proc_mnt_addr, vm = self.addr_space)
        proc_mnt = proc_mnt_ptr.dereference_as("vfsmount")

        root = proc_mnt.mnt_root

        for (hooked_member, hook_address) in self.verify_ops(root.d_inode.i_fop, f_op_members, modules):
            yield ("proc_mnt: root", hooked_member, hook_address)

        # only check the root directory
        for dentry in root.d_subdirs.list_of_type("dentry", "d_u"):

            name = dentry.d_name.name.dereference_as("String", length = 255)
            
            for (hooked_member, hook_address) in self.verify_ops(dentry.d_inode.i_fop, f_op_members, modules): 
                yield("proc_mnt: {0}".format(name), hooked_member, hook_address)
    
    def walk_proc(self, cur, f_op_members, modules, parent = ""):
 
        while cur:

            if cur.obj_offset in self.seen_proc:
                cur = cur.next
                continue

            self.seen_proc[cur.obj_offset] = 1

            name = cur.name.dereference_as("String", length = 255)

            fops = cur.proc_fops

            for (hooked_member, hook_address) in self.verify_ops(fops, f_op_members, modules):
                yield (name, hooked_member, hook_address)

            subdir = cur.subdir

            while subdir:
                for (name, hooked_member, hook_address) in self.walk_proc(subdir, f_op_members, modules):
                    yield (name, hooked_member, hook_address)
                subdir = subdir.next

            cur = cur.next

    def check_proc_root_fops(self, f_op_members, modules):   
        self.seen_proc = {}
 
        proc_root_addr = self.addr_space.profile.get_symbol("proc_root") 
        proc_root = obj.Object("proc_dir_entry", offset = proc_root_addr, vm = self.addr_space)

        for (hooked_member, hook_address) in self.verify_ops(proc_root.proc_fops, f_op_members, modules):
            yield("proc_root", hooked_member, hook_address)

        for (name, hooked_member, hook_address) in self.walk_proc(proc_root, f_op_members, modules):
            yield (name, hooked_member, hook_address)

    def calculate(self):
        linux_common.set_plugin_members(self)

        modules = linux_lsmod.linux_lsmod(self._config).get_modules()
            
        f_op_members = self.profile.types['file_operations'].keywords["members"].keys()
        f_op_members.remove('owner')

        if self._config.INODE:
            inode = obj.Object("inode", offset=self._config.INODE, vm=self.addr_space)
            if not inode.is_valid():
                debug.error("Invalid inode address given. Please use linux_find_file to determine valid inode addresses.")

            for (hooked_member, hook_address) in self.verify_ops(inode.i_fop, f_op_members, modules):
                yield("inode at {0:x}".format(inode.obj_offset), hooked_member, hook_address)
            
        else:
            funcs = [self.check_open_files_fop, self.check_proc_fop, self.check_proc_root_fops]

            for func in funcs:

                for (name, member, address) in func(f_op_members, modules):
                    yield (name, member, address)

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Symbol Name", "42"), 
                                  ("Member", "30"), 
                                  ("Address", "[addr]")])
                                  
        for (what, member, address) in data:
            self.table_row(outfd, what, member, address)


