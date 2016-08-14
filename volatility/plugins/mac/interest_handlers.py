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

kaddr_info = None

class mac_interest_handlers(common.AbstractMacCommand):
    """ Lists IOKit Interest Handlers """

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
   
    def parse_properties(self, fdict):
        props = {}

        ents = obj.Object('Array', offset = fdict.dictionary, 
                          vm = self.addr_space, 
                          targetType = self._struct_or_class("dictEntry"), 
                          count = fdict.count)

        # walk the current set of notifications
        for ent in ents:
            if ent == None or not ent.is_valid():
                continue

            key = str(ent.key.dereference_as(self._struct_or_class("OSString")))
            val = ent.value
 
            props[key] = val
    
        return props

    def walk_reg_entry(self, reg_addr):
        regroot = obj.Object(self._struct_or_class("IORegistryEntry"), offset = reg_addr, vm = self.addr_space)
        
        fdict = regroot.fRegistryTable

        props = self.parse_properties(regroot.fPropertyTable)

        ents = obj.Object('Array', offset = fdict.dictionary, 
                          vm = self.addr_space, 
                          targetType = self._struct_or_class("dictEntry"), 
                          count = fdict.count)

        keys     = []
        children = []
        current_name = ""
        device_mem = False

        for ent in ents:
            if ent == None or not ent.is_valid():
                continue
            
            key = str(ent.key.dereference_as(self._struct_or_class("OSString")))
            
            keys.append(key)
          
            if key == "IODeviceMemory":
                current_name = str(ent.value.dereference_as(self._struct_or_class("OSString")))
                device_mem = True
 
            if key == "IOName" and device_mem == False:
                current_name = str(ent.value.dereference_as(self._struct_or_class("OSString")))

            if key == "IOServiceChildLinks":
                children.append(ent.value)

        if current_name == "":
            if "IOClass" in props:
                addr = props["IOClass"]
                s = obj.Object(self._struct_or_class("OSString"), offset = addr, vm = self.addr_space)
                current_name = "IOCLass: %s" % str(s)

        if current_name == "":
            serv = obj.Object(self._struct_or_class("IOService"), offset = reg_addr, vm = self.addr_space)
            buf  = self.addr_space.read(serv.pwrMgt.Name, 128)           
            if buf:
                idx = buf.find("\x00")
                if idx != -1:
                    buf = buf[:idx]

                current_name = buf

        prop_string = "".join(["%s=%x, " % (k,v) for (k,v) in props.items()])

        #print "%-20s | %s | %s" % (current_name, keys, prop_string)

        offset = self.addr_space.profile.get_obj_offset(self._struct_or_class("_IOServiceInterestNotifier"), "chain")

        for (k, v) in props.items():
            if k.find("nterest") != -1:
                cmd = obj.Object(self._struct_or_class("IOCommand"), offset = v, vm = self.addr_space)
                notifier_ptr = cmd.fCommandChain.next
                first_ptr = notifier_ptr

                last = 0

                while notifier_ptr.is_valid() and notifier_ptr != last:
                    notifier = obj.Object(self._struct_or_class("_IOServiceInterestNotifier"), offset = notifier_ptr - offset, vm = self.addr_space)

                    if not notifier.handler.is_valid():
                        break
   
                    last = notifier_ptr
                    notifier_ptr = notifier.chain.next

                    if notifier_ptr == first_ptr:
                        break

                    handler = notifier.handler.v()

                    (module, handler_sym) = common.get_handler_name(kaddr_info, handler)

                    yield k, handler, module, handler_sym          
 
        for child in children: 
            for k, handler, module, handler_sym in self.walk_child_links(child):
                yield k, handler, module, handler_sym

    def walk_child_links(self, addr):
        val = obj.Object(self._struct_or_class("OSArray"), offset = addr, vm = self.addr_space)

        arr_ptr = val.array
        cnt = val.count

        arr = obj.Object(theType = "Array", targetType = "Pointer", offset = arr_ptr, count = cnt, vm = self.addr_space)

        for a in arr:
            for key, handler, module, handler_sym in self.walk_reg_entry(a):
                yield key, handler, module, handler_sym
            
    def calculate(self):
        common.set_plugin_members(self)
        
        global kaddr_info
        kaddr_info = common.get_handler_name_addrs(self)

        regroot_addr = common.get_cpp_sym("gRegistryRoot", self.addr_space.profile)
        p = obj.Object("Pointer", offset = regroot_addr, vm = self.addr_space)

        for key, handler, module, handler_sym in self.walk_reg_entry(p):
            yield key, handler, module, handler_sym 

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Interest", "24"),
                          ("Handler", "[addrpad]"),
                          ("Module", "32"),
                          ("Symbol", "")])

        for key, handler, module, handler_sym in data:
            self.table_row(outfd, key, handler, module, handler_sym)

