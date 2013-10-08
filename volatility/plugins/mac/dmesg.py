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
import volatility.plugins.mac.common as common

class mac_dmesg(common.AbstractMacCommand):
    """ Prints the kernel debug buffer """
    
    def calculate(self):
        common.set_plugin_members(self)

        msgbuf_ptr = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("_msgbufp"), vm = self.addr_space)
        msgbufp = msgbuf_ptr.dereference_as("msgbuf") 

        bufx = msgbufp.msg_bufx
        size = msgbufp.msg_size
        bufc = self.addr_space.read(msgbufp.msg_bufc, size)

        if bufc[bufx] == 0 and bufc[0] != 0:
            ## FIXME: can we do this without get_string?
            buf = common.get_string(bufc, self.addr_space)
        else:     
            if bufx > size:
                bufx = 0

            # older messages
            buf = bufc[bufx:bufx + size]
            buf = buf + bufc[0:bufx]

        # strip leading NULLs
        while ord(buf[0]) == 0x00:
            buf = buf[1:]

        yield buf

    def render_text(self, outfd, data):
        for buf in data:
            outfd.write("{0}\n".format(buf))
