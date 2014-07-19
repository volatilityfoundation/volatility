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

bash_vtypes = {
    'bash32_hist_entry': [ 0xc, {
    'line': [0x0, ['pointer', ['String', dict(length = 1024)]]],
    'timestamp': [0x4, ['pointer', ['String', dict(length = 1024)]]],
    'data': [0x8, ['pointer', ['void']]],
    }],
    
    'bash64_hist_entry': [ 24, {
    'line': [0, ['pointer', ['String', dict(length = 1024)]]],
    'timestamp': [8, ['pointer', ['String', dict(length = 1024)]]],
    'data': [16, ['pointer', ['void']]],
    }],
}

class _mac_hist_entry(obj.CType):
    """A class for history entries"""

    def is_valid(self):
        line_addr = self.line_ptr()        
        time_addr = self.time_ptr() 
 
        if (not obj.CType.is_valid(self) or  
                    not self.obj_vm.is_valid_address(line_addr) or 
                    not self.obj_vm.is_valid_address(time_addr)):
            return False

        ts = self.obj_vm.read(time_addr, 256)
        if not ts:
            return False
    
        idx = ts.find("\x00")
        if idx != -1:
            ts = ts[:idx]

        # At this point in time, the epoc integer size will 
        # never be less than 10 characters, and the stamp is 
        # always preceded by a pound/hash character. 
        if len(ts) < 10 or str(ts)[0] != "#":
            return False

        # The final check is to make sure the entire string
        # is composed of numbers. Try to convert to an int. 
        try:
            int(str(ts)[1:])
        except ValueError:
            return False 

        return True

    def line(self):
        line_addr = self.line_ptr()
        buf = self.obj_vm.read(line_addr, 256)
        if buf:
            idx = buf.find("\x00")
            if idx != -1:
                buf = buf[:idx]  

        return buf

    @property
    def time_as_integer(self):
        # Get the string and remove the leading "#" from the timestamp
        time_addr = self.time_ptr()
        ts = self.obj_vm.read(time_addr, 256)
        ts = ts[1:] 
        idx = ts.find("\x00")
        if idx != -1:
            ts = ts[:idx]
 
        # Convert the string into an integer (number of seconds)
        return int(ts)

    def time_object(self):
        nsecs = self.time_as_integer
        # Build a timestamp object from the integer 
        time_val = struct.pack("<I", nsecs)
        time_buf = addrspace.BufferAddressSpace(self.obj_vm.get_config(), data = time_val)
        time_obj = obj.Object("UnixTimeStamp", offset = 0, vm = time_buf, is_utc = True)
        return time_obj

    def line_ptr(self):
        addr = self.m("line").obj_offset
        return self.read_ptr(addr)

    def time_ptr(self):
        addr = self.m("timestamp").obj_offset
        return self.read_ptr(addr)

class bash64_hist_entry(_mac_hist_entry):
    def read_ptr(self, addr):
        addr = self.obj_vm.read(addr, 8)
        addr = struct.unpack("<Q", addr)[0]
        return addr

class bash32_hist_entry(_mac_hist_entry):
    def read_ptr(self, addr):
        addr = self.obj_vm.read(addr, 4)
        addr = struct.unpack("<I", addr)[0]
        return addr

class MacBashTypes(obj.ProfileModification):
    conditions = {"os" : lambda x : x in ["mac"]}

    def modification(self, profile):
        profile.vtypes.update(bash_vtypes)
        profile.object_classes.update({"bash32_hist_entry": bash32_hist_entry, "bash64_hist_entry": bash64_hist_entry})

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

                bit_string = str(task.task.map.pmap.pm_task_map or '')[9:]
                if bit_string.find("64BIT") == -1:
                    pack_format = "<I"
                    hist_struct = "bash32_hist_entry"
                else:
                    pack_format = "<Q"
                    hist_struct = "bash64_hist_entry"

                # Brute force the history list of an address isn't provided 
                ts_offset = proc_as.profile.get_obj_offset(hist_struct, "timestamp")

                history_entries = [] 
                bang_addrs = []

                # Look for strings that begin with pound/hash on the process heap 
                for ptr_hash in task.search_process_memory_rw_nofile(["#"]):                 
                    # Find pointers to this strings address, also on the heap 
                    addr = struct.pack(pack_format, ptr_hash)
                    bang_addrs.append(addr)

                for (idx, ptr_string) in enumerate(task.search_process_memory_rw_nofile(bang_addrs)):
                    # Check if we found a valid history entry object 
                    hist = obj.Object(hist_struct, 
                                      offset = ptr_string - ts_offset, 
                                      vm = proc_as)

                    if hist.is_valid():
                        history_entries.append(hist)
            
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
                           hist_entry.line())
            


