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
import volatility.plugins.mac.common as common
import volatility.plugins.mac.mount as mac_mount
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_list_files(common.AbstractMacCommand):
    """ Lists files in the file cache """

    def calculate(self):
        common.set_plugin_members(self)

        mounts = mac_mount.mac_mount(self._config).calculate()

        seen  = {}
        paths = {}

        for mount in mounts:
            vnode = mount.mnt_vnodelist.tqh_first

            while vnode:
                if vnode.v() in seen:
                    break
 
                seen[vnode.v()] = 1

                if vnode.v_flag.v() & 0x000001 != 0:
                    yield vnode, vnode.full_path()
                    
                    fname = ""
                    parent_vnode = None
                else:
                    fname = str(vnode.v_name.dereference() or '')
                    parent_vnode = vnode.v_parent

                if parent_vnode != None and fname != "":
                    parent_key = parent_vnode.v()

                    # if not then calc full path and store in cache
                    if not parent_key in paths:    
                        paths[parent_key] = parent_vnode.full_path()

                    if paths[parent_key] == "/":
                        sep = ""
                    else:
                        sep = "/"

                    # figure out our full path and store it
                    path = paths[parent_key] + sep + fname
                    paths[vnode.v()] = path
                    
                    yield vnode, path

                vnode = vnode.v_mntvnodes.tqe_next        
 
    def unified_output(self, data):
        return TreeGrid([("Offset (V)", Address),
                         ("File Path", str),
                         ], self.generator(data))

    def generator(self, data):
        for vnode, path in data:
            yield (0, [
                Address(vnode.v()),
                str(path),
            ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"), ("File Path", "")])
        for vnode, path in data:
            self.table_row(outfd, vnode.v(), path)    

