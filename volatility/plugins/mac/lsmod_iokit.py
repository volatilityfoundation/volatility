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
import volatility.debug as debug
import volatility.plugins.mac.common as common

class mac_lsmod_iokit(common.AbstractMacCommand):
    """ Lists loaded kernel modules through IOkit """

    def calculate(self):
        common.set_plugin_members(self)

        saddr  = common.get_cpp_sym("sLoadedKexts", self.addr_space.profile)

        p = obj.Object("Pointer", offset = saddr, vm = self.addr_space) 

        kOSArr = obj.Object("OSArray_class", offset = p, vm = self.addr_space)

        if kOSArr == None:
            debug.error("The OSArray_class type was not found in the profile. Please file a bug if you are running aginst Mac >= 10.7")

        kext_arr = obj.Object(theType  = "Array", targetType = "Pointer", offset = kOSArr.array, count = kOSArr.capacity, vm = self.addr_space)

        for (i, kext) in enumerate(kext_arr):
            kext = kext.dereference_as("OSKext_class")
            if kext and kext.is_valid():
                yield kext

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"),
                                  ("Module Address", "[addrpad]"), 
                                  ("Size", "8"), 
                                  ("Refs", "^8"),
                                  ("Version", "12"),  
                                  ("Name", "48"),
                                  ("Path", "")])
        for kext in data:
            path = kext.path

            if path:
                path = str(path.dereference())

            self.table_row(outfd,
                           kext.kmod_info,
                           kext.kmod_info.address, 
                           kext.kmod_info.m("size"),
                           kext.kmod_info.reference_count, 
                           kext.version,
                           kext.kmod_info.name, 
                           str(path))



