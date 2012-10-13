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

class mac_dmesg(mac_common.AbstractMacCommand):
    """ prints the kernel debug buffer """
    
    def calculate(self):

        msgbuf_ptr = obj.Object("Pointer", offset=self.smap["_msgbufp"], vm=self.addr_space)

        msgbufp    = obj.Object("msgbuf",  offset=msgbuf_ptr, vm=self.addr_space)

        bufx = msgbufp.msg_bufx
        size = msgbufp.msg_size
        bufc = self.addr_space.read(msgbufp.msg_bufc, size)
        

        if bufc[bufx] == 0 and bufc[0] != 0:
            buf = mac_common.get_string(bufc, self.addr_space)
 
        else:     
            if bufx > size:
                bufx = 0

            # older messages
            buf = bufc[bufx:bufx+size]
             
            buf = buf + bufc[0:bufx]

        yield buf

    def render_text(self, outfd, data):
        
        for buf in data:
            print buf

