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
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.lsmod as linux_lsmod
from volatility.plugins.linux.slab_info import linux_slabinfo
import volatility.plugins.linux.find_file as find_file
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_check_fop(linux_common.AbstractLinuxCommand):
    """Check file operation structures for rootkit modifications"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('INODE', short_option = 'i', default = None, help = 'inode to check', action = 'store', type='int')
        # to prevent multiple plugins from walking the process list
        self.tasks = []

    def check_file_cache(self, f_op_members, modules):
         for (_, _, file_path, file_dentry) in find_file.linux_find_file(self._config).walk_sbs():
            for (hooked_member, hook_address) in self.verify_ops(file_dentry.d_inode.i_fop, f_op_members, modules):
                yield (file_path, hooked_member, hook_address)

    def check_open_files_fop(self, f_op_members, modules):
        # get all the members in file_operations, they are all function pointers
        tasks = linux_pslist.linux_pslist(self._config).calculate()
        for task in tasks:
            self.tasks.append(task)
            for filp, i in task.lsof():
                for (hooked_member, hook_address) in self.verify_ops(filp.f_op, f_op_members, modules):
                    name = "{0:s} {1:d} {2:s}".format(task.comm, i, linux_common.get_path(task, filp))
                    yield (name, hooked_member, hook_address)
                    
    def check_proc_fop(self, f_op_members, modules):
        proc_mnt_addr = self.addr_space.profile.get_symbol("proc_mnt")
        
        if proc_mnt_addr:
            proc_mnt_ptr = obj.Object("Pointer", offset = proc_mnt_addr, vm = self.addr_space)
            proc_mnts    = [proc_mnt_ptr.dereference_as("vfsmount")]
        else:
            proc_mnts = []
            seen_pids = {}
                
            if self.addr_space.profile.obj_has_member("nsproxy", "pid_ns"):
                ns_member = "pid_ns"
            else:
                ns_member = "pid_ns_for_children"

            for task in self.tasks:
                nsp = task.nsproxy
                pidns = nsp.m(ns_member)

                if pidns.v() in seen_pids:
                    continue

                seen_pids[pidns.v()] = 1

                proc_mnts.append(pidns.proc_mnt)

        for proc_mnt in proc_mnts:
            root = proc_mnt.mnt_root

            for (hooked_member, hook_address) in self.verify_ops(root.d_inode.i_fop, f_op_members, modules):
                yield ("proc_mnt: root: %x" % root.v(), hooked_member, hook_address)

            # only check the root directory
            if self.addr_space.profile.obj_has_member("dentry", "d_child"):
                walk_member = "d_child"
            else:
                walk_member = "d_u"

            for dentry in root.d_subdirs.list_of_type("dentry", walk_member):
                name = dentry.d_name.name.dereference_as("String", length = 255)

                for (hooked_member, hook_address) in self.verify_ops(dentry.d_inode.i_fop, f_op_members, modules): 
                    yield("proc_mnt: {0:x}:{1}".format(root.v(), name), hooked_member, hook_address)

    def _get_name(self, pde, parent):
        if type(pde.name) == obj.Pointer:
            s = pde.name.dereference_as("String", length = 255)
        else:
            s = pde.obj_vm.read(pde.name.obj_offset, pde.namelen)
        
        return str(parent + "/" + str(s))

    def _walk_proc_old(self, cur, f_op_members, modules, parent):
        last_cur = None

        while cur:
            if cur.obj_offset in self.seen_proc:
                if cur.obj_offset == last_cur:
                    break

                cur = cur.next
                continue

            self.seen_proc[cur.obj_offset] = 1
                
            name = self._get_name(cur, parent)
            
            for (hooked_member, hook_address) in self.verify_ops(cur.proc_fops, f_op_members, modules):
                yield (name, hooked_member, hook_address)

            subdir = cur.subdir

            while subdir:
                for (subname, hooked_member, hook_address) in self._walk_proc_old(subdir, f_op_members, modules, name):
                    yield (subname, hooked_member, hook_address)
                subdir = subdir.next

            last_cur = cur.obj_offset
            cur = cur.next

    def _walk_rb(self, rb):
        nodes = []

        if not rb.is_valid():
             return nodes

        rboff = self.addr_space.profile.get_obj_offset("proc_dir_entry", "subdir_node")
        pde = obj.Object("proc_dir_entry", offset = rb.v() - rboff, vm = self.addr_space)
        
        nodes.append(pde)

        for pde2 in self._walk_rb(rb.rb_left):
            nodes.append(pde2)
 
        for pde3 in self._walk_rb(rb.rb_right):
            nodes.append(pde3)

        return nodes

    def _do_walk_proc_current(self, cur, f_op_members, modules, parent):
        nodes = []

        for pde in self._walk_rb(cur.subdir.rb_node):
            name = self._get_name(pde, parent)

            nodes.append((pde, name))
            
            nodes = nodes + self._do_walk_proc_current(pde, f_op_members, modules, name)

        return nodes

    def _walk_proc_current(self, cur, f_op_members, modules, parent):
        proc_entries = self._do_walk_proc_current(cur, f_op_members, modules, parent)

        for (pde, name) in proc_entries:
            for (hooked_member, hook_address) in self.verify_ops(pde.proc_fops, f_op_members, modules):
                yield (name, hooked_member, hook_address)

    def _walk_proc_dir(self, proc_root, f_op_members, modules, parent):
        if self.addr_space.profile.obj_has_member("proc_dir_entry", "subdir_node"):
            walk_proc = self._walk_proc_current
        else:
            walk_proc = self._walk_proc_old

        for (name, hooked_member, hook_address) in walk_proc(proc_root, f_op_members, modules, parent):
            yield (name, hooked_member, hook_address) 
        
    def check_proc_root_fops(self, f_op_members, modules):   
        self.seen_proc = {}
 
        proc_root_addr = self.addr_space.profile.get_symbol("proc_root") 
        proc_root = obj.Object("proc_dir_entry", offset = proc_root_addr, vm = self.addr_space)

        for (hooked_member, hook_address) in self.verify_ops(proc_root.proc_fops, f_op_members, modules):
            yield("proc_root", hooked_member, hook_address)
   
        for (name, hooked_member, hook_address) in self._walk_proc_dir(proc_root, f_op_members, modules, "/proc"):
            yield(name, hooked_member, hook_address)

    def check_proc_net_fops(self, f_op_members, modules):   
        nslist_addr = self.addr_space.profile.get_symbol("net_namespace_list")
        # < 2.6.23
        if not nslist_addr:
            return

        nethead = obj.Object("list_head", offset = nslist_addr, vm = self.addr_space)

        for net in nethead.list_of_type("net", "list"):
            for (name, hooked_member, hook_address) in self._walk_proc_dir(net.proc_net, f_op_members, modules, "/proc/net"):
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
            funcs = [self.check_open_files_fop, self.check_proc_fop, self.check_proc_root_fops, \
                    self.check_proc_net_fops, self.check_file_cache]
            
            for func in funcs:
                for (name, member, address) in func(f_op_members, modules):
                    yield (name, member, address)

    def unified_output(self, data):
        return TreeGrid([("SymbolName", str),
                       ("Member", str),
                       ("Address", Address)],
                        self.generator(data))

    def generator(self, data):
        for (what, member, address) in data:
            yield (0, [str(what), str(member), Address(address)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Symbol Name", "42"), 
                                  ("Member", "30"), 
                                  ("Address", "[addr]")])
                                  
        for (what, member, address) in data:
            self.table_row(outfd, what, member, address)

