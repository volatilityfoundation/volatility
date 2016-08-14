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

class mac_timers(common.AbstractMacCommand):
    """ Reports timers set by kernel drivers """

    def calculate(self):
        common.set_plugin_members(self)

        kaddr_info = common.get_handler_name_addrs(self)

        real_ncpus = obj.Object("int", offset = self.addr_space.profile.get_symbol("_real_ncpus"), vm = self.addr_space)
        
        ptr = self.addr_space.profile.get_symbol("_cpu_data_ptr")
        cpu_data_ptrs = obj.Object(theType = 'Array', offset = ptr, vm = self.addr_space, targetType = "unsigned long long", count = real_ncpus)
        
        for i in range(real_ncpus):
            cpu_data = obj.Object('cpu_data', offset = cpu_data_ptrs[i], vm = self.addr_space)

            c = cpu_data.rtclock_timer
            q = c.queue
            
            ent = q.head.next
            first = ent
            seen = {}

            while ent.is_valid():
                seen[ent.v()] = 1

                timer = obj.Object("call_entry", offset = ent.v(), vm = self.addr_space)
                  
                func = timer.func.v()

                if func < 0x1000 or func == 0xffffffff00000000:
                    break

                (module, handler_sym) = common.get_handler_name(kaddr_info, func)
                
                if hasattr(timer, "entry_time"):
                    entry_time = timer.entry_time.v()
                else:
                    entry_time = -1
                
                yield func, timer.param0, timer.param1, timer.deadline, entry_time, module, handler_sym       
         
                ent = timer.q_link.next

                if ent == first or ent.v() in seen:
                    break


    def render_text(self, outfd, data):
        self.table_header(outfd, [("Function", "[addrpad]"), 
                                  ("Param 0", "[addrpad]"), 
                                  ("Param 1", "[addrpad]"),
                                  ("Deadline", "16"),
                                  ("Entry Time", "16"),
                                  ("Module", "16"),
                                  ("Symbol", ""),
                                 ])

        for func, p0, p1, deadline, entry_time, module, sym in data:
            self.table_row(outfd, func, p0, p1, deadline, entry_time, module, sym)











