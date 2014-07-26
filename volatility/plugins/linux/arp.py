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

import socket
import volatility.plugins.linux.common as linux_common
import volatility.obj as obj

class a_ent(object):

    def __init__(self, ip, mac, devname):
        self.ip = ip
        self.mac = mac
        self.devname = devname

# based off pykdump
# not 100% this works, will need some testing to verify
class linux_arp(linux_common.AbstractLinuxCommand):
    """Print the ARP table"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        ntables_ptr = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("neigh_tables"), vm = self.addr_space)

        for ntable in linux_common.walk_internal_list("neigh_table", "next", ntables_ptr):
            for aent in self.handle_table(ntable):
                yield aent

    def handle_table(self, ntable):

        ret = []

        # FIXME: Consider using kernel version metadata rather than checking hasattr
        if hasattr(ntable, 'hash_mask'):
            hash_size = ntable.hash_mask
            hash_table = ntable.hash_buckets
        elif hasattr(ntable.nht, 'hash_mask'):
            hash_size = ntable.nht.hash_mask
            hash_table = ntable.nht.hash_buckets
        else:
            hash_size = (1 << ntable.nht.hash_shift)
            hash_table = ntable.nht.hash_buckets

        buckets = obj.Object(theType = 'Array', offset = hash_table, vm = self.addr_space, targetType = 'Pointer', count = hash_size)

        for i in range(hash_size):
            if buckets[i]:
                neighbor = obj.Object("neighbour", offset = buckets[i], vm = self.addr_space)

                ret.append(self.walk_neighbor(neighbor))

        # collapse all lists into one
        return sum(ret, [])

    def walk_neighbor(self, neighbor):

        ret = []

        for n in linux_common.walk_internal_list("neighbour", "next", neighbor):

            # get the family from each neighbour in order to work with ipv4 and 6
            family = n.tbl.family

            if family == socket.AF_INET:
                ip = obj.Object("IpAddress", offset = n.primary_key.obj_offset, vm = self.addr_space).v()
            elif family == socket.AF_INET6:
                ip = obj.Object("Ipv6Address", offset = n.primary_key.obj_offset, vm = self.addr_space).v()
            else:
                ip = '?'

            mac = ":".join(["{0:02x}".format(x) for x in n.ha][:n.dev.addr_len])
            devname = n.dev.name

            ret.append(a_ent(ip, mac, devname))

        return ret

    def render_text(self, outfd, data):
        for ent in data:
            outfd.write("[{0:42s}] at {1:20s} on {2:s}\n".format(ent.ip, ent.mac, ent.devname))
