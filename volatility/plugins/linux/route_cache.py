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
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_route_cache(linux_common.AbstractLinuxCommand):
    """ Recovers the routing cache from memory """

    def calculate(self):
        linux_common.set_plugin_members(self)

        mask_addr = self.addr_space.profile.get_symbol("rt_hash_mask")
        
        if mask_addr == None:
            debug.error("This plugin does not support this profile. The Linux routing cache was deleted in 3.6.x. See: https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=89aef8921bfbac22f00e04f8450f6e447db13e42")

        mask = obj.Object("unsigned int", offset = mask_addr, vm = self.addr_space)
        rt_pointer = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("rt_hash_table"), vm = self.addr_space)
        rt_hash_table = obj.Object(theType = "Array", offset = rt_pointer, vm = self.addr_space, targetType = "rt_hash_bucket", count = mask)

        # rt_do_flush / rt_cache_seq_show
        for i in range(mask):

            rth = rt_hash_table[i].chain

            if not rth:
                continue

            while rth:
 
                # FIXME: Consider using kernel version metadata rather than checking hasattr
                if hasattr(rth, 'u'):
                    dst = rth.u.dst
                    nxt = rth.u.dst.rt_next
                else:
                    dst = rth.dst
                    nxt = rth.dst.rt_next

                if dst.dev:
                    name = dst.dev.name
                else:
                    name = "*"

                dest = rth.rt_dst
                gw = rth.rt_gateway

                yield (name, dest, gw)

                rth = nxt

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Interface", "16"),
                                  ("Destination", "20"),
                                  ("Gateway", "")])

        for (name, dest, gw) in data:
            self.table_row(outfd, name, dest.cast("IpAddress"), gw.cast("IpAddress"))

