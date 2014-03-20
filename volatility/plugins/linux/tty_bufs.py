# Volatility
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
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: 504ENSICS Labs
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common


class linux_check_tty_rw(linux_common.AbstractLinuxCommand):
    """Checks tty devices for hooks"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        tty_addr = self.addr_space.profile.get_symbol("tty_drivers")
        
        if not tty_addr:
            debug.error("Symbol tty_drivers not found in kernel")
                        
        drivers = obj.Object("list_head", offset = tty_addr, vm = self.addr_space)
        
        sym_cache = {}

        for tty in drivers.list_of_type("tty_driver", "tty_drivers"):
            name = tty.name.dereference_as("String", length = linux_common.MAX_STRING_LENGTH)
            
            ttys = obj.Object("Array", targetType = "Pointer", vm = self.addr_space, offset = tty.ttys, count = tty.num)
            for tty_dev in ttys:
                if tty_dev == 0:
                    continue
                
                tty_dev = tty_dev.dereference_as("tty_struct")
                name = tty_dev.name

                r = tty_dev.read_buf
                w = tty_dev.write_buf
                e = tty_dev.echo_buf

                for a in [r, w, e]:
                    addr = a.obj_offset
                    print "0x%x" % addr
                    st = obj.Object("Pointer", offset = addr, vm = self.addr_space)
                    s = st.dereference_as("String", length=255)
                    if s.is_valid():
                        print str(s)


        yield ""

    def render_text(self, outfd, data):
        for blah in data:
            pass
