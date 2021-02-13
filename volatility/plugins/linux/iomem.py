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

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_iomem(linux_common.AbstractLinuxCommand):
    """Provides output similar to /proc/iomem"""

    def yield_resource(self, io_res, depth = 0):

        if not io_res:
            #print "null"
            return []

        name = io_res.name.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)
        start = io_res.start
        end = io_res.end

        output = [(depth, name, start, end)]

        output += self.yield_resource(io_res.child, depth + 1)
        output += self.yield_resource(io_res.sibling, depth)
        return output

    def calculate(self):
        linux_common.set_plugin_members(self)

        io_ptr = self.addr_space.profile.get_symbol("iomem_resource")
        io_res = obj.Object("resource", offset = io_ptr, vm = self.addr_space)

        for r in self.yield_resource(io_res.child):
            yield r

    def unified_output(self, data):
        return TreeGrid([("Name", str),
                         ("Start", Address),
                         ("End", Address)],
                        self.generator(data))

    def generator(self, data):
        for output in data:
            depth, name, start, end = output
            yield (0, [str(name), Address(start), Address(end)])

    def render_text(self, outfd, data):
        for output in data:
            depth, name, start, end = output
            outfd.write("{0:35s}\t0x{1:<16X}\t0x{2:<16X}\n".format(("  " * depth) + name, start, end))
