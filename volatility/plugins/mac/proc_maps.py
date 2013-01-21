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
import pslist
import common

class mac_proc_maps(pslist.mac_pslist):
    """ Gets memory maps of processes """

    def calculate(self):
        common.set_plugin_members(self)

        procs = pslist.mac_pslist.calculate(self)

        permask = "rwx"

        for proc in procs:
            task = obj.Object("task", offset=proc.task, vm=self.addr_space)

            hdr    = task.map.hdr

            numents = hdr.nentries 
            map     = hdr.links.next

            for i in xrange(0, numents):
                start = map.links.start
                end   = map.links.end
                perm  = map.protection
                perms = ""
           
                name = self.get_map_name(map)
           
                for (ctr, i) in enumerate([1, 3, 5]):
                    if (perm & i) == i:
                        perms = perms + permask[ctr]
                    else:
                        perms = perms + "-"

                yield (start, end, perms, name)

                map = map.links.next

    def render_text(self, outfd, data):
        for (start, end, perms, name) in data:
            outfd.write("{0:<16x} {1:<16x} {2} {3}\n".format(start, end, perms, name)) 

    def get_map_name(self, map):
        hdr = map.dereference()

        # TODO 
        if hdr.is_sub_map.v() == 1:
            return "sub_map" 

        ret = ""

        # find_vnode_object
        object = hdr.object.vm_object 

        while object.shadow.dereference() != None:
            object = object.shadow.dereference()

        ops = object.pager.mo_pager_ops.v()

        if ops == self.get_profile_symbol("_vnode_pager_ops"):
            vpager = obj.Object("vnode_pager", offset=object.pager, vm=self.addr_space)
            
            vnode  = vpager.vnode_handle

            ret = common.get_string(vnode.v_name, self.addr_space)

        return ret

     
                






