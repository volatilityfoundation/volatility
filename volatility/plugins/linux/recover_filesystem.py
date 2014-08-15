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

import volatility.obj   as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.find_file as linux_find_file

class linux_recover_filesystem(linux_common.AbstractLinuxCommand):
    """Recovers the entire cached file system from memory"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

    def _fix_metadata(self, file_path, file_dentry):
        inode = file_dentry.d_inode
        
        if inode and inode.is_valid():
            ents = file_path.split("/")
            out_path = os.path.join(self._config.DUMP_DIR, *ents)

            os.chmod(out_path, inode.i_mode & 00777)
            os.chown(out_path, inode.i_uid, inode.i_gid)
            os.utime(out_path, (inode.i_atime.tv_sec, inode.i_mtime.tv_sec))

    def _write_file(self, ff, file_path, file_dentry):
        inode = file_dentry.d_inode
        
        if inode and inode.is_valid() and not inode.is_dir():
            ents = file_path.split("/")
            out_path = os.path.join(self._config.DUMP_DIR, *ents)

            try:
                fd = open(out_path, "wb")
            except IOError, e:
                debug.warning("Unable to process file: %s : %s" % (out_path, str(e)))
                return
                
            for page in ff.get_file_contents(inode):
                fd.write(page)  
            
            fd.close()
            
    def _make_path(self, file_path, file_dentry):
        inode = file_dentry.d_inode
        
        if inode.is_dir():
            ents = file_path.split("/")
        else:
            ents = file_path.split("/")[:-1]

        out_path = os.path.join(self._config.DUMP_DIR, *ents)

        try:
            os.makedirs(out_path)
        except OSError:
            pass

    def calculate(self):
        linux_common.set_plugin_members(self)
        
        num_files = 0

        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")

        ff = linux_find_file.linux_find_file(self._config)

        for (_, _, file_path, file_dentry) in ff.walk_sbs():
            self._make_path(file_path, file_dentry)
            self._write_file(ff, file_path, file_dentry)
            self._fix_metadata(file_path, file_dentry)

            num_files = num_files + 1

        yield num_files

    def render_text(self, outfd, data):
        for (num_files) in data: 
            outfd.write("Recovered %d files\n" % num_files)

