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
import shutil

import volatility.obj   as obj
import volatility.debug as debug
import volatility.plugins.mac.common as mac_common
import volatility.plugins.mac.list_files as mac_list_files

class mac_recover_filesystem(mac_common.AbstractMacCommand):
    """Recover the cached filesystem"""

    def __init__(self, config, *args, **kwargs):
        mac_common.AbstractMacCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

    def _fix_metadata(self, vnode, path):
        if vnode and vnode.is_valid():
            # currently can only fix metadata of HFS files
            if vnode.v_tag != 16:
                return
            
            cnode = vnode.v_data.dereference_as("cnode")

            ents = path.split("/")
            out_path = os.path.join(self._config.DUMP_DIR, *ents)

            os.chmod(out_path, cnode.c_attr.ca_mode & 00777)
            os.chown(out_path, cnode.c_attr.ca_uid, cnode.c_attr.ca_gid)
            os.utime(out_path, (cnode.c_attr.ca_atime, cnode.c_attr.ca_mtime))

    def _write_file(self, vnode, out_path):
        if vnode and vnode.is_valid() and vnode.is_reg():
            ents = out_path.split("/")
            out_path = os.path.join(self._config.DUMP_DIR, *ents)

            # this is the ..namedfork/rsrc files. We currently skip those
            if os.path.exists(out_path) and os.path.isdir(out_path):
                shutil.rmtree(out_path) 

            if out_path.endswith("..namedfork/rsrc"):
                ret = 0
            else:
                mac_common.write_vnode_to_file(vnode, out_path)             
                ret = 1
        
        elif vnode.is_dir():
            ret = 1
        else:
            ret = 0

        return ret

    def _make_path(self, vnode, file_path):
        if vnode.is_dir():
            ents = file_path.split("/")
        elif vnode.is_reg():
            ents = file_path.split("/")[:-1]
        else:
            return 0

        out_path = os.path.join(self._config.DUMP_DIR, *ents)

        try:
            os.makedirs(out_path)
        except OSError:
            pass

        return 1

    def calculate(self):
        mac_common.set_plugin_members(self)
        
        num_files = 0

        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")

        ff = mac_list_files.mac_list_files(self._config)

        for (vnode, path) in ff.calculate():
            if self._make_path(vnode, path):
                if self._write_file(vnode, path):
                    self._fix_metadata(vnode, path)

                num_files = num_files + 1

        yield num_files

    def render_text(self, outfd, data):
        for (num_files) in data: 
            outfd.write("Recovered %d files\n" % num_files)

