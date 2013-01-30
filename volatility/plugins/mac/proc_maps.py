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

import volatility.obj as obj
import volatility.plugins.mac.pslist as pslist
import volatility.plugins.mac.common as common

class mac_proc_maps(pslist.mac_pslist):
    """ Gets memory maps of processes """

    def calculate(self):
        common.set_plugin_members(self)

        procs = pslist.mac_pslist.calculate(self)
        permask = "rwx"

        for proc in procs:
            task = proc.task.dereference_as("task") 
            map = task.map.hdr.links.next

            for i in xrange(task.map.hdr.nentries):
                start = map.links.start
                end = map.links.end
                perm = map.protection
                perms = ""
           
                name = self._get_path_for_map(map)
           
                for (ctr, i) in enumerate([1, 3, 5]):
                    if (perm & i) == i:
                        perms = perms + permask[ctr]
                    else:
                        perms = perms + "-"

                yield (proc, start, end, perms, name)
                map = map.links.next

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Start", "[addrpad]"),
                          ("End", "[addrpad]"),
                          ("Perms", "9"),
                          ("Map Name", "")])

        ## FIXME: [addrpad] gets truncated here for some reason
        for (proc, start, end, perms, name) in data:
            self.table_row(outfd, start, end, perms, name)

    def _get_vnode_for_map(self, map):
        hdr = map.dereference()

        # TODO 
        if hdr.is_sub_map.v() == 1:
            return "sub_map" 

        # find_vnode_object
        object = hdr.object.vm_object 

        while object.shadow.dereference() != None:
            object = object.shadow.dereference()

        ops = object.pager.mo_pager_ops.v()

        if ops == self.get_profile_symbol("_vnode_pager_ops"):
            vpager = obj.Object("vnode_pager", offset = object.pager, vm = self.addr_space)
            
            ret = vpager.vnode_handle
        else:
            ret = None

        return ret

    def _get_path_for_map(self, map):
        vnode = self._get_vnode_for_map(map)
    
        if type(vnode) == str and vnode == "sub_map":
            ret = vnode  
        elif vnode:
            path = []

            while vnode:
                path.append(str(vnode.v_name.dereference()))
                vnode = vnode.v_parent

            path.reverse()
            ret = "/".join(path)
        else:
            ret = ""
                
        return ret





