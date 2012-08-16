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

class linux_dmesg(linux_common.AbstractLinuxCommand):
    """Gather dmesg buffer"""

    def calculate(self):

        ptr_addr = self.smap["log_buf"]
        log_buf_addr = obj.Object("unsigned long", offset = ptr_addr, vm = self.addr_space)
        log_buf_len = obj.Object("int", self.smap["log_buf_len"], vm = self.addr_space)

        yield obj.Object("String", offset = log_buf_addr, vm = self.addr_space, length = log_buf_len)

    def render_text(self, outfd, data):

        for buf in data:
            outfd.write("{0:s}\n".format(buf))




