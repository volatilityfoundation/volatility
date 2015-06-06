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

import struct, string
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.mac.common  as mac_common
import volatility.plugins.mac.pstasks as mac_tasks
from volatility.renderers import TreeGrid

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

            ret = "".join([c for c in buf if c in string.printable])
        else:
            ret = ""

        return ret

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
        self._config.add_option('SCAN_ALL', short_option = 'A', default = False, help = 'scan all processes, not just those named bash', action = 'store_true')    

    def unified_output(self, data):
    
        return TreeGrid([("Pid", int), 
                            ("Name", str),
                            ("Command Time", str),
                            ("Command", str),
                            ], self.generator(data))
                            
    def generator(self, data):
        for task in data:
            if not (self._config.SCAN_ALL or str(task.p_comm) == "bash"):
                continue

            for hist_entry in task.bash_history_entries():
                yield (0, [
                    int(task.p_pid),
                    str(task.p_comm),
                    str(hist_entry.time_object()),
                    str(hist_entry.line()),
                    ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Command Time", "30"),
                                  ("Command", ""),])
                                    
        for task in data:
            if not (self._config.SCAN_ALL or str(task.p_comm) == "bash"):
                continue
            
            for hist_entry in task.bash_history_entries():
                self.table_row(outfd, task.p_pid, task.p_comm, 
                           hist_entry.time_object(), 
                           hist_entry.line())
