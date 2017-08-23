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
import volatility.obj   as obj
import volatility.utils as utils
import volatility.debug as debug

import volatility.plugins.mac.common as common

class mac_check_fop(common.AbstractMacCommand):
    """ Validate File Operation Pointers """

    def _walk_vfstbllist(self, kaddr_info):
        table_size_ptr = self.addr_space.profile.get_symbol("_maxvfsconf")

        if table_size_ptr == None:
            table_size_ptr = self.addr_space.profile.get_symbol("_maxvfsslots")

        table_size = obj.Object("unsigned int", offset = table_size_ptr, vm = self.addr_space)

        table_ptr = self.addr_space.profile.get_symbol("_vfstbllist")
        table = obj.Object(theType = "Array", targetType = "vfstable", offset = table_ptr, count = table_size, vm = self.addr_space) 
        vfs_op_members = self.profile.types['vfsops'].keywords["members"].keys()
        vfs_op_members.remove("vfs_reserved")

        for vfs in table:
            if not vfs.is_valid():
                continue

            name = self.addr_space.read(vfs.vfc_name.obj_offset, 16)
            if name:
                idx = name.find("\x00")
                if idx != -1:
                    name = name[:idx]
            else:
                name = "<INVALID NAME>"

            if name == "<unassigned>":
                break

            ops = vfs.vfc_vfsops

            for member in vfs_op_members:
                ptr = ops.__getattr__(member).v()

                if ptr == 0:
                    continue
                
                (module, handler_sym) = common.get_handler_name(kaddr_info, ptr)

                yield (vfs.v(), name, ptr, module, handler_sym)

    def _walk_opv_desc(self, kaddr_info):
        table_addr = self.addr_space.profile.get_symbol("_vfs_opv_descs")

        table = obj.Object(targetType = "unsigned long", theType = "Array", count = 32, vm = self.addr_space, offset = table_addr)

        for desc in table:
            if desc.v() == 0:
                break

            table_name = self.addr_space.profile.get_symbol_by_address("kernel", desc.v())
            if not table_name:
                table_name = "<unknown table>"

            vnodeopv_desc = obj.Object("vnodeopv_desc", offset = desc.v(), vm = self.addr_space)

            vdesc_arr = obj.Object(theType = "Array", targetType = "vnodeopv_entry_desc", offset = vnodeopv_desc.opv_desc_ops, count = 64, vm = self.addr_space)

            for vdesc in vdesc_arr: 
                ptr = vdesc.opve_impl.v()
                if ptr == 0:
                    break

                name = self.addr_space.read(vdesc.opve_op.vdesc_name.v(), 64)
                if name:
                    idx = name.find("\x00")
                    if idx != -1:
                        name = name[:idx]
                else:
                    name = "<INVALID NAME>"
                    
                name = table_name + "/" + name

                (module, handler_sym) = common.get_handler_name(kaddr_info, ptr)

                yield (vdesc.v(), name, ptr, module, handler_sym)  

    def calculate(self):
        common.set_plugin_members(self)
        
        kaddr_info = common.get_handler_name_addrs(self)

        funcs = [self._walk_opv_desc, self._walk_vfstbllist]

        for func in funcs:
            for (vfs_ptr, name, ptr, module, handler_sym) in func(kaddr_info):
                yield (vfs_ptr, name, ptr, module, handler_sym) 
    
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                          ("Name", "48"),
                          ("Handler", "[addrpad]"),
                          ("Module", "32"),
                          ("Handler Sym", "")])

        for (vfs_addr, name, handler, module, handler_sym) in data:
            self.table_row(outfd, vfs_addr, name, handler, module, handler_sym)

