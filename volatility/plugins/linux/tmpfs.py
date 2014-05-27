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

import os
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.mount  as linux_mount
import volatility.plugins.linux.find_file as linux_find_file

class linux_tmpfs(linux_common.AbstractLinuxCommand):
    '''Recovers tmpfs filesystems from memory'''

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'output directory for recovered files', action = 'store', type = 'str')
        config.add_option('SB', short_option = 'S', default = None, help = 'superblock to process, see -l', action = 'store', type = 'int')
        
        config.remove_option("LISTFILES")
        config.add_option('LIST_SBS', short_option = 'L', default = None, help = 'list avaiable tmpfs superblocks', action = 'store_true')

        # used to keep correct time for directories
        self.dir_times = {}

    def fix_md(self, new_file, perms, atime, mtime, isdir = 0):
        """Fix metadata for new files"""

        atime = atime.as_timestamp().v()
        mtime = mtime.as_timestamp().v()

        if isdir:
            self.dir_times[new_file] = (atime, mtime)
        else:
            os.utime(new_file, (atime, mtime))

        os.chmod(new_file, perms)

    def process_directory(self, dentry, _recursive = 0, parent = ""):

        for dentry in dentry.d_subdirs.list_of_type("dentry", "d_u"):
            name = dentry.d_name.name.dereference_as("String", length = 255)
            inode = dentry.d_inode

            if inode:
                new_file = os.path.join(parent, str(name))
                (perms, atime, mtime) = (inode.i_mode, inode.i_atime, inode.i_mtime)

                if inode.is_dir():
                    # since the directory may already exist
                    try:
                        os.mkdir(new_file)
                    except OSError:
                        pass

                    self.fix_md(new_file, perms, atime, mtime, 1)
                    self.process_directory(dentry, 1, new_file)

                elif inode.is_reg():
                    f = open(new_file, "wb")

                    for page in linux_find_file.linux_find_file(self._config).get_file_contents(inode):
                        f.write(page)

                    f = open(new_file, "wb")
                    f.close()
                    self.fix_md(new_file, perms, atime, mtime)

                # FUTURE add support for symlinks
                else:
                    #print "skipped: %s" % name
                    pass
            else:
                #print "no inode for %s" % name
                pass

    def walk_sb(self, root_dentry):

        cur_dir = os.path.join(self._config.DUMP_DIR)
        self.process_directory(root_dentry, parent = cur_dir)

        # post processing
        for new_file in self.dir_times:
            (atime, mtime) = self.dir_times[new_file]
            os.utime(new_file, (atime, mtime))

    def get_tmpfs_sbs(self):
        '''
        we need this b/c we have a bunch of 'super_block' structs
        but no method that I could find maps a super_block to its vfs_mnt
        which is needed to figure out where the super_block is mounted
    
        This function returns a hash table of hash[sb] = path
        '''

        ret = []
        mnts = linux_mount.linux_mount(self._config).calculate()

        for (sb, _dev_name, path, fstype, _rr, _mnt_string) in linux_mount.linux_mount(self._config).parse_mnt(mnts):
            if str(fstype) == "tmpfs":
                ret.append((sb, path))

        return ret

    def calculate(self):
        linux_common.set_plugin_members(self)

        # a list of root directory entries
        if self._config.DUMP_DIR and self._config.SB:

            if not os.path.isdir(self._config.DUMP_DIR):
                debug.error(self._config.DUMP_DIR + " is not a directory")

            # this path never 'yield's, just writes the filesystem to disk
            tmpfs_sbs = self.get_tmpfs_sbs()
            sb_idx = self._config.SB - 1

            if sb_idx >= len(tmpfs_sbs):
                debug.error("Invalid superblock number given. Please use the -L option to determine valid numbers.")
        
            root_dentry = tmpfs_sbs[sb_idx][0].s_root
            self.walk_sb(root_dentry)

        elif self._config.LIST_SBS:

            # vfsmnt.mnt_sb.s_root
            tmpfs_sbs = self.get_tmpfs_sbs()

            for (i, (_sb, path)) in enumerate(tmpfs_sbs):
                yield (i + 1, path)
        else:
            debug.error("No sb number/output directory combination given and list superblocks not given")

    # we only render the -L option
    def render_text(self, outfd, data):
        for (i, path) in data:
            outfd.write("{0:d} -> {1}\n".format(i, path))

