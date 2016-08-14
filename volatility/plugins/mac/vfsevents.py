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
import volatility.debug as debug
import volatility.plugins.mac.common as common

class mac_vfsevents(common.AbstractMacCommand):
    """ Lists processes filtering file system events """

    def calculate(self):
        common.set_plugin_members(self)

        if not self.addr_space.profile.obj_has_member("fs_event_watcher", "proc_name"):
            debug.error("This plugin only supports OS X >= 10.8.2. Please file a bug if you are running against a version matching this criteria.")

        event_types = ["CREATE_FILE", "DELETE", "STAT_CHANGED", "RENAME", "CONTENT_MODIFIED", "EXCHANGE", "FINDER_INFO_CHANGED", "CREATE_DIR", "CHOWN"]
        event_types = event_types + ["XATTR_MODIFIED", "XATTR_REMOVED", "DOCID_CREATED", "DOCID_CHANGED"]

        table_addr = self.addr_space.profile.get_symbol("_watcher_table")
    
        arr = obj.Object(theType = "Array", targetType = "Pointer", count = 8, vm = self.addr_space, offset = table_addr)

        for watcher_addr in arr:
            if not watcher_addr.is_valid():
                continue

            watcher = watcher_addr.dereference_as("fs_event_watcher")

            name = self.addr_space.read(watcher.proc_name.obj_offset, 33)
            if name:
                idx = name.find("\x00")
                if idx != -1:
                    name = name[:idx]

            events = ""
            event_arr = obj.Object(theType = "Array", targetType = "unsigned char", offset = watcher.event_list.v(), count = 13, vm = self.addr_space)
            for (i, event) in enumerate(event_arr):
                if event == 1:
                    events = events + event_types[i] + ", "  

            if len(events) and events[-1] == " " and events[-2] == ",":
                events = events[:-2]

            yield watcher_addr, name, watcher.pid, events

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                          ("Name", "20"),
                          ("Pid", "8"),
                          ("Events", "")])
        
        for (addr, name, pid, events) in data:
            self.table_row(outfd, addr, name, pid, events)
