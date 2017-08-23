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
import volatility.plugins.mac.common as common
import volatility.plugins.mac.mount as mac_mount
import volatility.obj as obj

class mac_list_files(common.AbstractMacCommand):
    """ Lists files in the file cache """

    def __init__(self, config, *args, **kwargs):
        common.AbstractMacCommand.__init__(self, config, *args, **kwargs)
        
        self._config.add_option('SHOW_ORPHANS', 
            short_option = 's', 
            default = False, 
            help = 'Show orphans (vnodes without a parent)', 
            action = 'store_true')

    @staticmethod
    def list_files(config):
    
        plugin = mac_mount.mac_mount(config)
        mounts = plugin.calculate()
        vnodes = {}
        parent_vnodes = {}

        ## build an initial table of all vnodes 
        for mount in mounts:
            vnode = mount.mnt_vnodelist.tqh_first.dereference()

            while vnode:
                ## abort here to prevent going in a loop 
                if vnode.obj_offset in vnodes:
                    break
                 
                ## its ok to call the slower full_path() 
                ## here because its only done for root 
                ## nodes which is only a couple per system
                if int(vnode.v_flag) & 1:
                    name  = vnode.full_path()
                
                    entry = [name, None, vnode]
                    vnodes[vnode.obj_offset] = entry
 
                else:
                    name = vnode.v_name.dereference()
                    parent = vnode.v_parent.dereference()
                
                    if parent:
                        par_offset = parent.obj_offset 
                    else: 
                        if config.SHOW_ORPHANS:
                            par_offset = None
                        else:
                            vnode = vnode.v_mntvnodes.tqe_next.dereference() 
                            continue
            
                    entry = [name, par_offset, vnode]
                    vnodes[vnode.obj_offset] = entry
                
                vnode = vnode.v_mntvnodes.tqe_next.dereference() 

        ## account for vnodes that aren't in the list but are 
        ## referenced from other vnode's v_parent pointers 
        for key, val in vnodes.items():
            name, parent, vnode = val    
            
            if not name or not parent:
                continue
                
            parent = obj.Object("vnode", 
                offset = parent, 
                vm = vnode.obj_vm)
                
            while parent:
            
                if parent.obj_offset in vnodes:
                    break

                name = parent.v_name.dereference()
                next_parent = parent.v_parent.dereference()
            
                if next_parent:
                    par_offset = next_parent.obj_offset 
                else: 
                    par_offset = None
        
                entry = [str(name), par_offset, parent]
                vnodes[parent.obj_offset] = entry
                
                parent = next_parent  

        ## build the full paths for all directories
        for key, val in vnodes.items():
            name, parent, vnode = val

            ## we can't have unnamed files or directories
            if not name:
                continue
    
            if not vnode.is_dir():
                continue
  
            name = str(name)
            
            if parent in parent_vnodes:
                full_path = parent_vnodes[parent] + "/" + name
            else:
                paths = [name]
                while parent:
                    entry = vnodes.get(parent)
                
                    ## a vnode's parent wasn't found or 
                    ## we reached the root directory 
                    if not entry:
                        break
                    
                    name, parent, _vnode = entry
                    if not name:
                        break
                    
                    paths.append(str(name))
                
                ## build the path in reverse order 
                full_path = "/".join(reversed(paths))
                
            parent_vnodes[key] = full_path

        ## link everything up with their parents 
        for val in vnodes.values():
            name, parent, vnode = val
            
            if not name:
                continue
           
            name = str(name)
 
            entry = parent_vnodes.get(parent) 
            if not entry:
                yield vnode, name
            else:
                full_path = entry + "/" + name
                
                ## add a leading slash if one doesn't exist
                if full_path[0] != "/":
                    full_path = "/" + full_path
                    
                ## otherwise in some cases we may have double 
                ## slashes so reduce that down to just one 
                elif full_path[0:2] == "//":
                    full_path = full_path[1:]

                yield vnode, full_path

    def calculate(self):
        common.set_plugin_members(self)
        config = self._config
        
        for result in mac_list_files.list_files(config):
            yield result

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"), ("File Path", "")])
        for vnode, path in data:
            self.table_row(outfd, vnode.obj_offset, path)    
