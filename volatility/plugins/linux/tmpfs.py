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
@organization:
"""

import sys, os
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.mount as linux_mount
import volatility.plugins.linux.flags as linux_flags
import volatility.debug as debug
import volatility.utils as utils

class linux_tmpfs(linux_common.AbstractLinuxCommand):

    ''' recovers tmpfs filesystems from memory '''

    def __init__(self, config, *args):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('EVIDENCE_DIR', short_option = 'o', default = None, help = 'output directory for recovered files',      action = 'store', type = 'str')
        self._config.add_option('SB',           short_option = 'S', default = None, help = 'superblock to process, see -l',             action = 'store', type = 'int')
        self._config.add_option('LIST_SBS',     short_option = 'L', default = None, help = 'list avaiable tmpfs superblocks',           action = 'store_true')

        # used to keep correct time for directories
        self.dir_times = {}

    # fix metadata for new files
    def fix_md(self, new_file, perms, atime, mtime, isdir=0):

        # FIXME
        atime = atime.tv_sec + 18000
        mtime = mtime.tv_sec + 18000

        if isdir:
            self.dir_times[new_file] = (atime, mtime)
        else:
            os.utime(new_file, (atime, mtime))

        os.chmod(new_file, perms)

    def process_directory(self, dentry, recursive=0, parent=""):

        for dentry in dentry.d_subdirs.list_of_type("dentry", "d_u"):

            name = dentry.d_name.name.dereference_as("String", length=255)

            inode = dentry.d_inode
            
            if inode:
                               
                new_file = os.path.join(parent, name)
              
                (perms, size, atime, mtime) = (inode.i_mode, inode.i_size, inode.i_atime, inode.i_mtime)
 
                if linux_common.S_ISDIR(inode.i_mode):
                    # since the directory may already exist
                    try:
                        os.mkdir(new_file)
                    except:
                        pass

                    self.fix_md(new_file, perms, atime, mtime, 1)

                    self.process_directory(dentry, 1, new_file)
                    
                elif linux_common.S_ISREG(inode.i_mode):
        
                    contents = linux_common.get_file_contents(self, inode)

                    f = open(new_file, "wb")
                    f.write(contents)
                    f.close()
                    self.fix_md(new_file, perms, atime, mtime)

                # TODO add support for symlinks
                else:
                    #print "skipped: %s" % name
                    pass
            else:
                #print "no inode for %s" % name
                pass

    def walk_sb(self, root_dentry):

        cur_dir = os.path.join(self.edir)

        self.process_directory(root_dentry, parent=cur_dir)
    
        # post processing
        for new_file in self.dir_times:
            (atime, mtime) = self.dir_times[new_file]

            os.utime(new_file, (atime, mtime))

    '''
    we need this b/c we have a bunch of 'super_block' structs
    but no method that I could find maps a super_block to its vfs_mnt
    which is needed to figure out where the super_block is mounted

    This function returns a hash table of hash[sb] = path
    '''
    def get_tmpfs_sbs(self):

        ret = []

        mnt_points = linux_mount.linux_mount(self._config).calculate()

        for (sb, _dev_name, path, fstype, _rr, _mnt_string) in mnt_points:

            if str(fstype) == "tmpfs":

                ret.append((sb, path))

        return ret

    def calculate(self):

        self.edir     = self._config.EVIDENCE_DIR
        self.sb_num   = self._config.SB
        self.list_sbs = self._config.LIST_SBS

         # a list of root directory entries
      
        if self.edir and self.sb_num:
    
            if not os.path.isdir(self.edir):
                debug.error(self.edir + " is not a directory")
 
            # this path never 'yield's, just writes the filesystem to disk
            tmpfs_sbs = self.get_tmpfs_sbs()
            
            # FIXME - validate
            root_dentry = tmpfs_sbs[self.sb_num - 1][0].s_root
            
            self.walk_sb(root_dentry)

        elif self.list_sbs:

            # vfsmnt.mnt_sb.s_root
            tmpfs_sbs = self.get_tmpfs_sbs()

            for (i, (sb, path)) in enumerate(tmpfs_sbs):

                yield (i + 1, path)

        else:
            debug.error("No sb number/output directory combination given and list superblocks not given")

    # we only render the -L option
    def render_text(self, outfd, data):
    
        for (i, path) in data:

            outfd.write("{0:d} -> {1}\n".format(i, path))

