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

import struct
from operator import attrgetter
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.mac.common  as mac_common
import volatility.plugins.mac.pstasks as mac_tasks

class mac_bash(mac_tasks.mac_tasks):
    """Recover bash history from bash process memory"""

    def __init__(self, config, *args, **kwargs): 
        mac_tasks.mac_tasks.__init__(self, config, *args, **kwargs)
        self._config.add_option('PRINTUNALLOC', short_option = 'P', default = None, help = 'print unallocated entries, please redirect to a file', action = 'store_true')
        self._config.add_option('HISTORY_LIST', short_option = 'H', default = None, help = 'address from history_list - see the Volatility wiki', action = 'store', type = 'long')        
        self._config.add_option('SCAN_ALL', short_option = 'A', default = False, help = 'scan all processes, not just those named bash', action = 'store_true')    

    def calculate(self):
        mac_common.set_plugin_members(self)
    
        tasks = mac_tasks.mac_tasks(self._config).calculate()

        for task in tasks:
            proc_as = task.get_process_address_space()
            
            if not self._config.HISTORY_LIST:
                # Do we scan everything or just /bin/bash instances?
                if not (self._config.SCAN_ALL or str(task.p_comm) == "bash"):
                    continue

                # Keep a bucket of history objects so we can order them
                history_entries = []

                # Brute force the history list of an address isn't provided 
                ts_offset = proc_as.profile.get_obj_offset("_hist_entry", "timestamp") 

                # Are we dealing with 32 or 64-bit pointers
                if proc_as.profile.metadata.get('memory_model', '32bit') == '32bit':
                    pack_format = "I"
                else:
                    pack_format = "Q"

                # Look for strings that begin with pound/hash on the process heap 
                for ptr_hash in task.search_process_memory_rw_nofile(["#"]):                   
 
                    # Find pointers to this strings address, also on the heap 
                    addr = struct.pack(pack_format, ptr_hash)

                    for ptr_string in task.search_process_memory_rw_nofile([addr]):
                        
                        # Check if we found a valid history entry object 
                        hist = obj.Object("_hist_entry", 
                                          offset = ptr_string - ts_offset, 
                                          vm = proc_as)

                        if hist.is_valid():
                            history_entries.append(hist)
                            # We can terminate this inner loop now 
                            break
                
                # Report everything we found in order
                for hist in sorted(history_entries, key = attrgetter('time_as_integer')):
                    yield task, hist              
            else:    
                the_history_addr = the_history_addr = self._config.HISTORY_LIST
                the_history = obj.Object("Pointer", vm = proc_as, offset = the_history_addr)
                max_ents = 2001
                the_history = obj.Object(theType = 'Array', offset = the_history, 
                                         vm = proc_as, targetType = 'Pointer', 
                                         count = max_ents)

                for ptr in the_history:
                    if not ptr:
                        if self._config.PRINTUNALLOC:
                            continue
                        else:
                            break

                    hist = ptr.dereference_as("_hist_entry")      
    
                    if hist.is_valid():
                        yield task, hist
    
    def render_text(self, outfd, data):

        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Command Time", "30"),
                                  ("Command", ""),])
                                    
        for task, hist_entry in data:
            self.table_row(outfd, task.p_pid, task.p_comm, 
                           hist_entry.time_object(), 
                           hist_entry.line.dereference())
            


