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
import mac_common
import datetime

class mac_route(mac_common.AbstractMacCommand):

    def get_table(self, tbl):

        rnh = tbl #obj.Object("radix_node", offset=tbl.v(), vm=self.addr_space)
        rn  = rnh.rnh_treetop
        
        while rn.rn_bit >= 0:
            rn = rn.rn_u.rn_node.rn_L

        rnhash = {}

        while 1:
            
            base = rn
            
            if rn in rnhash:
                break

            rnhash[rn] = 1

            while rn.rn_parent.rn_u.rn_node.rn_R == rn and rn.rn_flags & 2 == 0:
                rn = rn.rn_parent

            rn = rn.rn_parent.rn_u.rn_node.rn_R

            while rn.rn_bit >= 0:
                rn = rn.rn_u.rn_node.rn_L

            nextptr = rn

            while base.v() != 0:
    
                rn   = base
                base = rn.rn_u.rn_leaf.rn_Dupedkey

                if rn.rn_flags & 2 == 0:
                    rt = obj.Object("rtentry", offset=rn, vm=self.addr_space)
                    yield rt

            rn = nextptr

            if rn.rn_flags & 2 != 0:
                break
            
    def calculate(self):

        tables_addr = self.smap["_rt_tables"]

        ents = obj.Object(theType = 'Array', offset = tables_addr, vm = self.addr_space, targetType = 'Pointer', count = 32)

        ipv4table = obj.Object("radix_node_head", offset=ents[2], vm=self.addr_space)

        rts = self.get_table(ipv4table)

        for rt in rts:
            yield rt

    def render_text(self, outfd, data):
        for rt in data:
            mac_common.print_rt(self, rt)


