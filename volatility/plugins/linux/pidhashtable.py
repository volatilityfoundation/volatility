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
import volatility.debug as debug

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.find_file as find_file

PIDTYPE_PID = 0

# determining the processing algorithm to use is based on crash from redhat
class linux_pidhashtable(linux_pslist.linux_pslist):
    """Enumerates processes through the PID hash table"""

    def __init__(self, *args, **kwargs):
        self.seen_tasks = {}
        linux_pslist.linux_pslist.__init__(self, *args, **kwargs)

    def get_obj(self, ptr, sname, member):
        offset = self.profile.get_obj_offset(sname, member)
        addr   = ptr - offset
        return obj.Object(sname, offset = addr, vm = self.addr_space)

    def _task_for_pid(self, upid, pid):

        chained = 0

        pid_tasks_0 = pid.tasks[0].first
        
        if pid_tasks_0 == 0:
            chained = 1
            pnext_addr = upid.obj_offset + self.profile.get_obj_offset("upid", "pid_chain") + self.profile.get_obj_offset("hlist_node", "next")
            pnext = obj.Object("unsigned long", offset = pnext_addr, vm = self.addr_space)
            upid = obj.Object("upid", offset = pnext - self.profile.get_obj_offset("upid", "pid_chain"), vm = self.addr_space)
            for task in self._walk_upid(upid):
                yield task

        if chained == 0:
            task = obj.Object("task_struct", offset = pid_tasks_0 - self.profile.get_obj_offset("task_struct", "pids"), vm = self.addr_space)
            if task.pid > 0:
                yield task

    def _walk_upid(self, upid):
        seen = set()
        while upid and upid.is_valid() and upid.v() not in seen:
            seen.add(upid.v())

            pid = self.get_obj(upid.obj_offset, "pid", "numbers")

            for task in self._task_for_pid(upid, pid):
                yield task

            if type(upid.pid_chain) == obj.Pointer:
                pid_chain = obj.Object("hlist_node", offset = upid.pid_chain.obj_offset, vm = self.addr_space)
            else:
                pid_chain = upid.pid_chain

            if not pid_chain:
                break

            upid = self.get_obj(pid_chain.next, "upid", "pid_chain")

    def _get_pidhash_array(self):
        pidhash_shift = obj.Object("unsigned int", offset = self.addr_space.profile.get_symbol("pidhash_shift"), vm = self.addr_space)
        pidhash_size = 1 << pidhash_shift

        pidhash_addr = self.addr_space.profile.get_symbol("pid_hash")
        pidhash_ptr = obj.Object("Pointer", offset = pidhash_addr, vm = self.addr_space)

        # pidhash is an array of hlist_heads
        pidhash = obj.Object(theType = 'Array', offset = pidhash_ptr, vm = self.addr_space, targetType = 'hlist_head', count = pidhash_size)

        return pidhash

    def calculate_v3(self):
        self.seen_tasks = {}

        pidhash = self._get_pidhash_array()

        seen_upid = set()

        for hlist in pidhash:
            # each entry in the hlist is a upid which is wrapped in a pid
            ent = hlist.first

            while ent.v():
                upid = self.get_obj(ent.obj_offset, "upid", "pid_chain")

                if upid.v() in seen_upid:
                    break
                seen_upid.add(upid.v())

                for task in self._walk_upid(upid):
                    if not task.obj_offset in self.seen_tasks:
                        self.seen_tasks[task.obj_offset] = 1
                        if task.is_valid_task():
                            yield task

                ent = ent.m("next")

    # the following functions exist because crash has handlers for them
    # but I was unable to find a profile/kernel that needed them (maybe too old or just a one-off distro kernel
    # if someone actually triggers this message, I can quickly add in the support as I will have a sample to test again
    def profile_unsupported(self, func_name):
        debug.error("{0:s}: This profile is currently unsupported by this plugin. Please file a bug report on our issue tracker to have support added.".format(func_name))

    def calculate_v2(self):
        poff = self.addr_space.profile.get_obj_offset("task_struct", "pids") 

        pidhash    = self._get_pidhash_array()

        for p  in pidhash:
            if p.v() == 0:
                continue
            
            ptr = obj.Object("Pointer", offset = p.v(), vm = self.addr_space)
    
            if ptr.v() == 0:
                continue

            pidl = obj.Object("pid_link", offset = ptr.v(), vm = self.addr_space)

            nexth = pidl.pid

            if not nexth.is_valid():
                continue
         
            nexth = obj.Object("task_struct", offset = nexth - poff, vm = self.addr_space)

            while 1:
                if not pidl:
                    break

                yield nexth
               
                pidl = pidl.node.m("next").dereference_as("pid_link")    
                
                nexth = pidl.pid

                if not nexth.is_valid():
                    break
 
                nexth = obj.Object("task_struct", offset = nexth - poff, vm = self.addr_space)

    def calculate_v1(self):
        self.profile_unsupported("calculate_v1")

    def refresh_pid_hash_task_table(self):
        self.profile_unsupported("refresh_pid_hash_task_table")

    def get_both(self):
        has_pid_link = self.profile.has_type("pid_link")
        has_link_pid = self.profile.obj_has_member("pid_link", "pid")

        has_pid_hash = self.profile.has_type("pid_hash")
        has_upid = self.profile.has_type("upid")
        has_pid_numbers = self.profile.obj_has_member("pid", "numbers")

        if has_pid_hash:
            has_hash_chain = self.profile.obj_has_member("pid_hash", "chain")
        else:
            has_hash_chain = None

        if has_link_pid and has_hash_chain:
            func = self.refresh_pid_hash_task_table

        elif has_pid_link:
            if has_upid and has_pid_numbers:
                func = self.calculate_v3 # refresh_hlist_task_table_v3
            else:
                func = self.calculate_v2 # refresh_hlist_task_table_v2
        else:
            func = self.calculate_v1

        return func

    def radix_tree_is_internal_node(self, ptr):
        if hasattr(ptr, "v"):
            ptr = ptr.v()

        return ptr & 3 == 1

    def radix_tree_is_indirect_ptr(self, ptr):
        return ptr & 1

    def radix_tree_indirect_to_ptr(self, ptr):
        return obj.Object("radix_tree_node", offset = ptr & ~1, vm = self.addr_space)


    def _walk_idr_node(self, node, height, idx):
        for i in range(self.RADIX_TREE_MAP_SIZE):
            shift = (height - 1) * self.RADIX_TREE_MAP_SHIFT  

            slot = node.slots[i]

            if slot == 0:
                continue

            slot = self.radix_tree_indirect_to_ptr(slot)

            if height == 1:
                yield slot
            else:
                child_index = idx | (i << shift)
                for child_slot in self._walk_idr_node(slot, height - 1, child_index):
                    yield child_slot

    # adapted from tools.c of crash
    def _walk_pid_ns_idr(self):
        self.RADIX_TREE_MAP_SHIFT = 6
        self.RADIX_TREE_MAP_SIZE = 1 << self.RADIX_TREE_MAP_SHIFT
        self.RADIX_TREE_MAP_MASK = self.RADIX_TREE_MAP_SIZE - 1

        ns_addr = self.addr_space.profile.get_symbol("init_pid_ns")
        ns = obj.Object("pid_namespace", offset = ns_addr, vm = self.addr_space)
        
        root = ns.idr.idr_rt

        node = root.rnode
        if not node.is_valid():
            return 

        height = 0

        if hasattr(node, "height"):
            height = node.height

            if height == 0:
                height = 1

        is_indirect = self.radix_tree_is_indirect_ptr(node)
        node = self.radix_tree_indirect_to_ptr(node)
        
        if is_indirect and hasattr(node, "shift"):
            height = (node.shift / self.RADIX_TREE_MAP_SHIFT) + 1

        if height == 0:
            yield node  
        else:
            for child_node in self._walk_idr_node(node, height, 0):
                yield child_node

    def _task_for_radix_pid_node(self, node):
        pid = obj.Object("pid", offset = node.v(), vm = self.addr_space)

        pid_tasks_0 = pid.tasks[0].first

        if pid_tasks_0 == 0:
            task = None
        else:
            if self.addr_space.profile.obj_has_member("task_struct", "pids"):
                offset = self.addr_space.profile.get_obj_offset("task_struct", "pids")
            elif self.addr_space.profile.obj_has_member("task_struct", "pid_links"):
                offset = self.addr_space.profile.get_obj_offset("task_struct", "pid_links")
            else:
                debug.error("Unable to determine task_struct pids member")
            
            task = obj.Object("task_struct", offset = pid_tasks_0 - offset, vm = self.addr_space)
      
        return task 
    
    def _do_walk_xarray(self, ff, node, height, index):
        shift = (height - 1) * self.XA_CHUNK_SHIFT
        
        for i in range(self.XA_CHUNK_SIZE):
            slot = ff.xa_get_entry_from_offset(i, node)
            if slot == None:
                continue

            if (slot.v() & self.XARRAY_TAG_MASK) == self.XARRAY_TAG_INTERNAL:
                slot = obj.Object("xa_node", offset = slot.v() & ~self.XARRAY_TAG_INTERNAL, vm = self.addr_space)

            if height == 1:
                yield slot   
            else:
                new_index = index | (i << shift)
                for new_slot in self._do_walk_xarray(ff, slot, height - 1, new_index):
                    yield new_slot 

    def _walk_xarray_pids(self):
        ff = find_file.linux_find_file(self._config)
        linux_common.set_plugin_members(ff)

        self.XARRAY_TAG_MASK     = 3
        self.XARRAY_TAG_INTERNAL = 2

        self.XA_CHUNK_SHIFT = 6
        self.XA_CHUNK_SIZE  = 1 << self.XA_CHUNK_SHIFT
        self.XA_CHUNK_MASK  = self.XA_CHUNK_SIZE - 1

        ns_addr = self.addr_space.profile.get_symbol("init_pid_ns")
        ns = obj.Object("pid_namespace", offset = ns_addr, vm = self.addr_space)
 
        xarray = ns.idr.idr_rt

        if not xarray.is_valid():
            return

        root = xarray.xa_head.v()

        is_internal = ff.xa_is_internal(root)

        if root & self.XARRAY_TAG_MASK != 0:
            root = root & ~self.XARRAY_TAG_MASK

        height = 0
        node   = obj.Object("xa_node", offset = root, vm = self.addr_space)
        
        if is_internal and hasattr(node, "shift"):
            height = (node.shift / self.XA_CHUNK_SHIFT) + 1

        for node in self._do_walk_xarray(ff, node, height, 0):
            if node and node.is_valid():
                yield node

    def pid_namespace_idr(self):
        if not self.addr_space.profile.has_type("radix_tree_root"):
            func = self._walk_xarray_pids
        elif self.addr_space.profile.obj_has_member("radix_tree_root", "rnode"):
            func = self._walk_pid_ns_idr
        else:
            func = self._walk_xarray_pids

        for node in func():
            task = self._task_for_radix_pid_node(node)
            if task != None:
                yield task    

    def determine_func(self):
        pidhash = self.addr_space.profile.get_symbol("pidhash")
        pid_hash = self.addr_space.profile.get_symbol("pid_hash")
        pidhash_shift = self.addr_space.profile.get_symbol("pidhash_shift")
        pid_idr  = self.profile.obj_has_member("pid_namespace", "idr")

        if pid_hash and pidhash_shift:
            func = self.get_both()

        elif pid_hash:
            func = self.refresh_pid_hash_task_table

        elif pidhash:
            func = self.refresh_pid_hash_task_table

        elif pid_idr:
            func = self.pid_namespace_idr            

        else:
            self.profile_unsupported("determine_func")             

        return func

    def calculate(self):
        linux_common.set_plugin_members(self)
        func = self.determine_func()
        
        for task in func():
            if 0 < task.pid < 66000:
                if task.parent.is_valid():
                    yield task






