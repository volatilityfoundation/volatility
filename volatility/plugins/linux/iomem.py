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
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common

class linux_iomem(linux_common.AbstractLinuxCommand):
    """Provides output similar to /proc/iomem"""

    def yield_resource(self, io_ptr, depth = 0):

        if not io_ptr:
            #print "null"
            return []

        io_res = obj.Object("resource", offset = io_ptr, vm = self.addr_space)

        name = io_res.name.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)
        start = io_res.start
        end = io_res.end

        output = [ (depth, name, start, end)]

        output += self.yield_resource(io_res.child, depth + 1)
        output += self.yield_resource(io_res.sibling, depth)
        return output

    def calculate(self):

        io_ptr = self.get_profile_symbol("iomem_resource")

        for r in self.yield_resource(io_ptr):
            yield r

    def render_text(self, outfd, data):

        for output in data:
            depth, name, start, end = output
            outfd.write("{0:35s}\t0x{1:<16X}\t0x{2:<16X}\n".format(("  " * depth) + name, start, end))
