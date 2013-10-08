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

import sys, os
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.mount as linux_mount
import volatility.plugins.linux.flags as linux_flags
import volatility.debug as debug
import volatility.utils as utils

class linux_find_file(linux_common.AbstractLinuxCommand):
    '''Recovers tmpfs filesystems from memory'''

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('FIND',  short_option = 'F', default = None, help = 'file (path) to find', action = 'store', type = 'str')
        self._config.add_option('INODE', short_option = 'i', default = None, help = 'inode to write to disk', action = 'store', type = 'int')
        self._config.add_option('OUTFILE', short_option = 'O', default = None, help = 'output file path', action = 'store', type = 'str')

    def _walk_sb(self, dentry_param, last_dentry, parent):
        if last_dentry == None or last_dentry != dentry_param.v():
            last_dentry = dentry_param
        else:
            return

        ret = None

        for dentry in dentry_param.d_subdirs.list_of_type("dentry", "d_u"):
            if not dentry.d_name.name.is_valid():
                continue

            inode = dentry.d_inode
            name  = dentry.d_name.name.dereference_as("String", length = 255)

            # do not use os.path.join
            # this allows us to have consistent paths from the user
            new_file = parent + "/" + name

            yield new_file, dentry

            if inode and inode.is_dir():
                for new_file, dentry in self._walk_sb(dentry, last_dentry, new_file):
                    yield new_file, dentry
    
    def _get_sbs(self):
        ret = []
        mnts = linux_mount.linux_mount(self._config).calculate()

        for (sb, _dev_name, path, fstype, _rr, _mnt_string) in linux_mount.linux_mount(self._config).parse_mnt(mnts):
            ret.append((sb, path))

        return ret

    def walk_sbs(self):
        ret = None
        sbs = self._get_sbs()

        for (sb, sb_path) in sbs:
            if sb_path != "/":
                parent = sb_path
            else:
                parent = ""

            for vals in self._walk_sb(sb.s_root, None, parent):
                if vals:
                    (file_path, file_dentry) = vals
                    yield (sb, sb_path, file_path, file_dentry)
            
    def calculate(self):
        linux_common.set_plugin_members(self)

        find_file  = self._config.FIND
        inode_addr = self._config.inode        
        outfile    = self._config.outfile

        if find_file and len(find_file):
            for (_, _, file_path, file_dentry) in self.walk_sbs():
                if file_path == find_file:
                    yield file_dentry
                    break

        elif inode_addr and inode_addr > 0 and outfile and len(outfile) > 0:
            inode = obj.Object("inode", offset = inode_addr, vm = self.addr_space)
            
            contents = self.get_file_contents(inode)

            f = open(outfile, "wb")
            f.write(contents)
            f.close()

        else:
            debug.error("Incorrect command line parameters given.")

    def render_text(self, outfd, data):

        shown_header = 0

        for dentry in data:

            if not shown_header:
                self.table_header(outfd, [("Inode Number", "16"), ("Inode", "[addr]")])
                shown_header = 1

            inode     = dentry.d_inode
            inode_num = inode.i_ino

            self.table_row(outfd, inode_num, inode)
            
    # from here down is code to walk the page cache and mem_map / mem_section page structs#
    def radix_tree_is_indirect_ptr(self, ptr):
        return ptr & 1

    def radix_tree_indirect_to_ptr(self, ptr):
        return obj.Object("radix_tree_node", offset = ptr & ~1, vm = self.addr_space)

    def radix_tree_lookup_slot(self, root, index):
        self.RADIX_TREE_MAP_SHIFT = 6
        self.RADIX_TREE_MAP_SIZE = 1 << self.RADIX_TREE_MAP_SHIFT
        self.RADIX_TREE_MAP_MASK = self.RADIX_TREE_MAP_SIZE - 1

        node = root.rnode

        if self.radix_tree_is_indirect_ptr(node) == 0:

            if index > 0:
                return None

            off = root.obj_offset + self.profile.get_obj_offset("radix_tree_root", "rnode")
            page = obj.Object("Pointer", offset = off, vm = self.addr_space)
            return page

        node = self.radix_tree_indirect_to_ptr(node)
        height = node.height
        shift = (height - 1) * self.RADIX_TREE_MAP_SHIFT
        slot = -1

        while 1:
            idx = (index >> shift) & self.RADIX_TREE_MAP_MASK
            slot = node.slots[idx]
            shift = shift - self.RADIX_TREE_MAP_SHIFT
            height = height - 1
            if height <= 0:
                break

        if slot == -1:
            return None

        return slot

    def SHMEM_I(self, inode):
        offset = self.profile.get_obj_offset("shmem_inode_info", "vfs_inode")
        return obj.Object("shmem_inode_info", offset = inode.obj_offset - offset, vm = self.addr_space)

    def find_get_page(self, inode, offset):
        page = self.radix_tree_lookup_slot(inode.i_mapping.page_tree, offset)

        #if not page:
            # FUTURE swapper_space support
            # print "no page"

        return page

    def get_page_contents(self, inode, idx):
        page_addr = self.find_get_page(inode, idx)

        if page_addr:
            page = obj.Object("page", offset = page_addr, vm = self.addr_space)
            phys_offset = page.to_paddr()
            phys_as = utils.load_as(self._config, astype = 'physical')
            data = phys_as.zread(phys_offset, 4096)
        else:
            data = "\x00" * 4096

        return data

    # main function to be called, handles getting all the pages of an inode
    # and handles the last page not being page_size aligned 
    def get_file_contents(self, inode):
        linux_common.set_plugin_members(self)
        data = ""
        file_size = inode.i_size
        extra = file_size % 4096
        idxs = file_size / 4096

        if extra != 0:
            extra = 4096 - extra
            idxs = idxs + 1

        for idx in range(0, idxs):
            data = data + self.get_page_contents(inode, idx)

        # this is chop off any extra data on the last page

        if extra != 0:
            extra = extra * -1
            data = data[:extra]

        return data



