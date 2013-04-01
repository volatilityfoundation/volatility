# Volatility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: 
"""

import struct
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.linux.common  as linux_common
import volatility.plugins.linux.pslist as linux_pslist

bash_vtypes_32 = {
    '_hist_entry': [ 0xc, {
    'line': [0x0, ['pointer', ['String', dict(length = 1024)]]],
    'timestamp': [0x4, ['pointer', ['String', dict(length = 1024)]]],
    'data': [0x8, ['pointer', ['void']]],
    }],
}

bash_vtypes_64 = {
    '_hist_entry': [ 24, {
    'line': [0, ['pointer', ['String', dict(length = 1024)]]],
    'timestamp': [8, ['pointer', ['String', dict(length = 1024)]]],
    'data': [16, ['pointer', ['void']]],
    }],
}

class _hist_entry(obj.CType):

    def is_valid(self):
        return (obj.CType.is_valid(self) and 
                    self.line.is_valid() and 
                    len(self.line.dereference()) and 
                    self.timestamp.is_valid() and 
                    len(self.timestamp.dereference()))

    def time_object(self):
        # Get the string and remove the leading "#" from the timestamp 
        time_string = str(self.timestamp.dereference())[1:] 
        # Convert the string into an integer (number of seconds)
        nsecs = int(time_string)
        # Build a timestamp object from the integer 
        time_val = struct.pack("<I", nsecs)
        time_buf = addrspace.BufferAddressSpace(self.obj_vm.get_config(), data = time_val)
        time_obj = obj.Object("UnixTimeStamp", offset = 0, vm = time_buf, is_utc = True)
        return time_obj

class BashTypes(obj.ProfileModification):

    def modification(self, profile):
        
        if profile.metadata.get('memory_model', '32bit') == "32bit":
            profile.vtypes.update(bash_vtypes_32)
        else:
            profile.vtypes.update(bash_vtypes_64)

        profile.object_classes.update({"_hist_entry": _hist_entry})

class linux_bash(linux_pslist.linux_pslist):
    """Recover bash history from bash process memory"""

    def __init__(self, config, *args, **kwargs): 
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('PRINTUNALLOC', short_option = 'P', default = None, help = 'print unallocated entries, please redirect to a file', action = 'store_true')
        self._config.add_option('HISTORY_LIST', short_option = 'H', default = None, help = 'address from history_list - see the Volatility wiki', action = 'store', type = 'long')        
    
    def calculate(self):
        linux_common.set_plugin_members(self)
    
        tasks = linux_pslist.linux_pslist(self._config).calculate()

        if not self._config.HISTORY_LIST:
            debug.error("History list address not specified.")
        
        the_history_addr = self._config.HISTORY_LIST

        for task in tasks:
            proc_as = task.get_process_address_space()
            
            # In cases when mm is an invalid pointer 
            if not proc_as:
                continue

            the_history = obj.Object("Pointer", vm = proc_as, offset = the_history_addr)

            max_ents = 2001

            the_history = obj.Object(theType = 'Array', offset = the_history, vm = proc_as, targetType = 'Pointer', count = max_ents)

            for ptr in the_history:
                if not ptr:
                    if self._config.PRINTUNALLOC:
                        continue
                    else:
                        break

                hist = obj.Object("_hist_entry", offset = ptr, vm = proc_as)       
    
                if hist.is_valid():
                    yield hist
    
    def render_text(self, outfd, data):

        self.table_header(outfd, [("Command Time", "30"),
                                  ("Command", ""),])
                                    
        for hist_entry in data:
            self.table_row(outfd, 
                           hist_entry.time_object(), 
                           hist_entry.line.dereference())
            


