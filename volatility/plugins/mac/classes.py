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

class mac_kernel_classes(common.AbstractMacCommand):
    """ Lists loaded c++ classes in the kernel """

    def _struct_or_class(self, type_name):
        """Return the name of a structure or class. 

        More recent versions of OSX define some types as 
        classes instead of structures, so the naming is
        a little different.   
        """
        if self.addr_space.profile.vtypes.has_key(type_name):
            return type_name
        else:
            return type_name + "_class"
   
    def calculate(self):
        common.set_plugin_members(self)
        
        kaddr_info = common.get_handler_name_addrs(self)

        dict_ptr_addr = common.get_cpp_sym("sAllClassesDict", self.addr_space.profile)     
        dict_addr = obj.Object("unsigned long", offset = dict_ptr_addr, vm = self.addr_space)

        fdict = obj.Object(self._struct_or_class("OSDictionary"), offset = dict_addr.v(), vm = self.addr_space)
        
        ents = obj.Object('Array', offset = fdict.dictionary, 
                          vm = self.addr_space, 
                          targetType = self._struct_or_class("dictEntry"), 
                          count = fdict.count)

        for ent in ents:
            if ent == None or not ent.is_valid():
                continue
            
            class_name = str(ent.key.dereference_as(self._struct_or_class("OSString")))
           
            osmeta = obj.Object(self._struct_or_class("OSMetaClass"), offset = ent.value.v(), vm = self.addr_space)

            cname = str(osmeta.className.dereference_as(self._struct_or_class("OSString")))
            
            offset = 0

            if hasattr(osmeta, "metaClass"):
                arr_start = osmeta.metaClass.v()
            else:
                arr_start = obj.Object("Pointer", offset = osmeta.obj_offset, vm = self.addr_space)

            vptr = obj.Object("unsigned long", offset = arr_start, vm = self.addr_space)
            while vptr != 0:
                (module, handler_sym) = common.get_handler_name(kaddr_info, vptr)

                yield (cname, vptr, module, handler_sym)
                
                offset = offset + vptr.size()

                vptr = obj.Object("unsigned long", offset = arr_start + offset, vm = self.addr_space)
    
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Class", "48"),
                                  ("Address", "[addrpad]"),
                                  ("Module", "48"),
                                  ("Handler", "")])

        for (cname, vptr, module, handler_sym) in data:
            self.table_row(outfd, cname, vptr, module, handler_sym) 












