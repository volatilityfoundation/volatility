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
import datetime
import volatility.obj as obj
import volatility.plugins.mac.common as common
from volatility.renderers import TreeGrid

class mac_route(common.AbstractMacCommand):
    """ Prints the routing table """

    def _get_table(self, tbl):
        rnh = tbl #obj.Object("radix_node", offset=tbl.v(), vm=self.addr_space)
        rn = rnh.rnh_treetop
        
        while rn.is_valid() and rn.rn_bit >= 0:
            rn = rn.rn_u.rn_node.rn_L

        rnhash = {}

        while rn.is_valid():
            base = rn
            
            if rn in rnhash:
                break

            rnhash[rn] = 1

            while rn.is_valid() and rn.rn_parent.rn_u.rn_node.rn_R == rn and rn.rn_flags & 2 == 0:
                rn = rn.rn_parent

            rn = rn.rn_parent.rn_u.rn_node.rn_R

            while rn.is_valid() and rn.rn_bit >= 0:
                rn = rn.rn_u.rn_node.rn_L

            nextptr = rn

            while base.v() != 0:
    
                rn = base
                base = rn.rn_u.rn_leaf.rn_Dupedkey

                if rn.rn_flags & 2 == 0:
                    rt = obj.Object("rtentry", offset = rn, vm = self.addr_space)
                    yield rt

            rn = nextptr

            if rn.rn_flags & 2 != 0:
                break
            
    def calculate(self):
        common.set_plugin_members(self)

        tables_addr = self.addr_space.profile.get_symbol("_rt_tables")

        ## FIXME: if we only use ents[2] why do we need to instantiate 32?
        ents = obj.Object('Array', offset = tables_addr, vm = self.addr_space, targetType = 'Pointer', count = 32)

        ipv4table = obj.Object("radix_node_head", offset = ents[2], vm = self.addr_space)

        rts = self._get_table(ipv4table)

        for rt in rts:
            yield rt

    def unified_output(self, data):

        return TreeGrid([("Source IP", str), 
                        ("Dest. IP", str),
                        ("Name", str),
                        ("Sent", int),
                        ("Recv", int),
                        ("Time", str),
                        ("Exp.", int),
                        ("Delta", int)
                        ], self.generator(data))
    def generator(self, data):
        for rt in data:
            yield (0, [
                    str(rt.source_ip), 
                    str(rt.dest_ip),
                    str(rt.name),
                    int(rt.sent),
                    int(rt.rx),
                    str(rt.get_time()), 
                    int(rt.expire()),
                    int(rt.delta),
                    ])    

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Source IP", "24"), 
                                  ("Dest. IP", "24"), 
                                  ("Name", "^10"), 
                                  ("Sent", "^18"),
                                  ("Recv", "^18"), 
                                  ("Time", "^30"), 
                                  ("Exp.", "^10"), 
                                  ("Delta", "")])

        for rt in data:
            self.table_row(outfd, 
                           rt.source_ip, 
                           rt.dest_ip,
                           rt.name,
                           rt.sent, rt.rx, 
                           rt.get_time(), 
                           rt.expire(), 
                           rt.delta)
