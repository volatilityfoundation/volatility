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
import volatility.plugins.mac.common as common
import volatility.plugins.mac.list_files as mac_list_files

class mac_devfs(common.AbstractMacCommand):
    """ Lists files in the file cache """

    def calculate(self):
        common.set_plugin_members(self)

        nchrdev_addr = self.addr_space.profile.get_symbol("_nchrdev")
        nchrdev = obj.Object("unsigned int", offset = nchrdev_addr, vm = self.addr_space)

        cdevsw_addr = self.addr_space.profile.get_symbol("_cdevsw")
        cdevsw = obj.Object(theType = "Array", targetType = "cdevsw", offset = cdevsw_addr, vm = self.addr_space, count = nchrdev)

        kaddr_info = common.get_handler_name_addrs(self)

        op_members = self.profile.types['cdevsw'].keywords["members"].keys()
        
        op_members.remove('d_ttys')
        op_members.remove('d_type')

        files = mac_list_files.mac_list_files(self._config).calculate()
        for vnode, path in files:
            if vnode.v_type.v() not in [3, 4]:
                continue

            if path.startswith("/Macintosh HD"):
                path = path[13:]

            dn = vnode.v_data.dereference_as("devnode") 
 
            dev   = dn.dn_typeinfo.dev
            major = (dev >> 24) & 0xff

            if not (0 <= major <= nchrdev):
                continue
        
            cdev = cdevsw[major]
           
            for member in op_members:
                ptr = cdev.__getattr__(member).v()
        
                if ptr != 0: 
                    (module, handler_sym) = common.get_handler_name(kaddr_info, ptr)

                    yield (cdev.v(), path, member, ptr, module, handler_sym)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"), 
                                  ("Path", "16"),
                                  ("Member", "16"),
                                  ("Handler", "[addrpad]"),
                                  ("Module",  "32"),
                                  ("Handler", "")])

        for (cdev, path, member, handler, module, sym) in data:
            self.table_row(outfd, cdev, path, member, handler, module, sym)


 
