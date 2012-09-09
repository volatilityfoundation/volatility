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

    def _get_log_info(self):

        ptr_addr = self.get_profile_symbol("log_buf")
        log_buf_addr = obj.Object("unsigned long", offset = ptr_addr, vm = self.addr_space)
        log_buf_len = obj.Object("int", self.get_profile_symbol("log_buf_len"), vm = self.addr_space)

        return (log_buf_addr, log_buf_len)

    # pre 3.x
    def _pre_3(self, buf_addr, buf_len):
        
        return obj.Object("String", offset = buf_addr, vm = self.addr_space, length = buf_len)

    def _ver_3(self, buf_addr, buf_len):
        '''
        During 3.x, the kernel switched the kernel debug buffer from just a big char array to the variable now
        holding variable sized records tracked by inline 'log' structures
        We deal with this by walking all the logs and building the buffer up and then returning it
        This produces the same results as the old way
        '''    
        
        ret = ""
        
        size_of_log = self.profile.get_obj_size("log")
        
        cur_addr = buf_addr
        end_addr = buf_addr + buf_len
        
        log = obj.Object("log", offset = cur_addr, vm = self.addr_space)
        cur_len = log.len

        while cur_addr < end_addr and cur_len != 0:

            msg_len = log.text_len
            cur_ts = log.ts_nsec

            buf = obj.Object("String", offset = cur_addr + size_of_log, vm = self.addr_space, length = msg_len)
        
            ret = ret + "[{0}.{1}] {2}\n".format(cur_ts, cur_ts / 1000000000, buf)
            
            cur_addr = cur_addr + cur_len

            log = obj.Object("log", offset=cur_addr, vm=self.addr_space)
            cur_len = log.len

        return ret

    def calculate(self):
        linux_common.set_plugin_members(self)    
        (log_buf_addr, log_buf_len) = self._get_log_info()

        if self.profile.has_type("log") and self.profile.obj_has_member("log", "ts_nsec"):
            yield self._ver_3(log_buf_addr, log_buf_len)

        else:
            yield self._pre_3(log_buf_addr, log_buf_len)

    def render_text(self, outfd, data):

        for buf in data:
            outfd.write("{0:s}\n".format(buf))




