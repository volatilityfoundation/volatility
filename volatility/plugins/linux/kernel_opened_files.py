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
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers.basic import Address
from volatility.renderers import TreeGrid

class linux_kernel_opened_files(linux_common.AbstractLinuxCommand):
    """Lists files that are opened from within the kernel"""

    def _walk_node_hash(self, node):
        last_node = None
        cnt = 0

        hash_offset = self.addr_space.profile.get_obj_offset("dentry", "d_hash")
        while node.is_valid() and node != last_node:
            if cnt > 0:
                yield node, cnt

            dentry = obj.Object("dentry", offset = node.v() - hash_offset, vm = self.addr_space)
            cnt = cnt + 1
            last_node = node
            node = dentry.d_hash.next

    def _walk_node_node(self, node):
        last_node = None
        cnt = 0

        while node.is_valid() and node != last_node:
            if cnt > 0:
                yield node, cnt

            cnt = cnt + 1
            last_node = node
            node = node.next

    def _walk_node(self, node):
        last_node = None

        yield node, 0

        for node, cnt in self._walk_node_node(node):
            yield node, cnt

        for node, cnt in self._walk_node_hash(node):
            yield node, cnt

    def _gather_dcache(self):
        d_hash_shift = obj.Object("unsigned int", offset =self.addr_space.profile.get_symbol("d_hash_shift"), vm = self.addr_space)
        loop_max = 1 << d_hash_shift

        d_htable_ptr = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("dentry_hashtable"), vm = self.addr_space)

        arr = obj.Object(theType = "Array", targetType = "hlist_bl_head", offset = d_htable_ptr, vm = self.addr_space, count = loop_max)

        hash_offset = self.addr_space.profile.get_obj_offset("dentry", "d_hash")

        dents = {}

        for list_head in arr:
            if not list_head.first.is_valid():
                continue


            node = obj.Object("hlist_bl_node", offset = list_head.first & ~1, vm = self.addr_space)

            for node, cnt in self._walk_node(node):
                dents[node.v() - hash_offset] = 0

        return dents

    def _compare_filps(self):
        dcache = self._gather_dcache()

        tasks = linux_pslist.linux_pslist(self._config).calculate()
        for task in tasks:
            for filp, i in task.lsof():
                val = filp.dentry.v()
                if not val in dcache:
                    yield val

        procs = linux_pslist.linux_pslist(self._config).calculate()
        for proc in procs:
            for vma in proc.get_proc_maps():
                if vma.vm_file:
                    val = vma.vm_file.dentry.v()
                    if not val in dcache:
                        yield val

    def calculate(self):
        linux_common.set_plugin_members(self)

        for dentry_offset in self._compare_filps():
            dentry = obj.Object("dentry", offset = dentry_offset, vm = self.addr_space)
            if dentry.d_count > 0 and dentry.d_inode.is_reg() and dentry.d_flags == 128:
                yield dentry

    def generator(self,data):
        for dentry in data:
            yield(0,Address(dentry.obj_offset),str(dentry.get_partial_path()))

    def unified_output(self, data):
        return TreeGrid([("Offset (V)",Address),
                        ("Partial File Path",str)],
                        self.generator(data))

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Offset (V)", "[addrpad]"),
                                  ("Partial File Path", "")])
        for dentry in data:
            self.table_row(outfd, dentry.obj_offset, dentry.get_partial_path())
