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

import volatility.obj as obj
import volatility.debug as debug
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

class BashTypes(obj.ProfileModification):

    def modification(self, profile):
        
        if profile.metadata.get('memory_model', '32bit') == "32bit":
            profile.vtypes.update(bash_vtypes_32)
        else:
            profile.vtypes.update(bash_vtypes_64)

class linux_bash(linux_pslist.linux_pslist):

    def __init__(self, config, *args): 
        linux_pslist.linux_pslist.__init__(self, config, *args)
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

                # FIXME .deference_as("String") doesn't take vm=
                # d = hist.line.dereference_as("String", length=255, vm=proc_as)
                # t = hist.timestamp.dereference_as("String", length=255, vm=proc_as)            
    
                cmd = hist.line.dereference()
                cmdtime = hist.timestamp.dereference()

                if cmd and len(cmd) and cmdtime and len(cmdtime):
                    yield (cmd, cmdtime)
    
    def render_text(self, outfd, data):

        self.table_header(outfd, [("Command Time", "20"),
                                  ("Command", ""),])
                                    
        for (cmd, cmdtime) in data:
            self.table_row(outfd, cmdtime, cmd)
            


