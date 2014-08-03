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

import os

import volatility.obj as obj
import volatility.plugins.mac.pstasks as pstasks 
import volatility.plugins.mac.common as common

class mac_adium(pstasks.mac_tasks):
    """ Lists Adium messages """

    def __init__(self, config, *args, **kwargs):         
        pstasks.mac_tasks.__init__(self, config, *args, **kwargs)         
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')
        self._config.add_option('WIDE', short_option = 'W', default = False, help = 'Wide character search', action = 'store_true')
 
    def _make_uni(self, msg):
        if self._config.WIDE:
            return "\x00".join([m for m in msg])
        else:
            return msg

    def calculate(self):
        common.set_plugin_members(self)

        procs = pstasks.mac_tasks.calculate(self)

        for proc in procs:
            if proc.p_comm.lower().find("adium") == -1:
                continue
            
            proc_as = proc.get_process_address_space()

            for map in proc.get_proc_maps():
                if map.get_perms() != "rw-" or map.get_path() != "":
                    continue

                buffer = proc_as.zread(map.start.v(), map.end.v() - map.start.v())

                if not buffer:
                    continue

                msg_search  = self._make_uni('<span class="x-message"')
                time_search = self._make_uni('<span class="x-ltime"')
                send_search = self._make_uni('<span class="x-sender"')
                end_search  = self._make_uni('</span>')

                idx     = 0
                msg_idx = buffer.find(msg_search)

                while msg_idx != -1:
                    idx = idx + msg_idx

                    msg_end_idx = buffer[idx:].find(end_search)
                    
                    if msg_end_idx == -1:
                       break

                    msg = buffer[idx: idx + msg_end_idx + 14]

                    # to look for time and send
                    search_idx = idx - 200 

                    time_idx = buffer[search_idx : search_idx + 200].find(time_search)
                            
                    msg_time = ""

                    if time_idx != -1:
                        time_end_idx = buffer[search_idx + time_idx: search_idx + time_idx + 130].find(end_search)
                        
                        if time_end_idx != -1:
                            msg_time = buffer[search_idx + time_idx:  search_idx + time_idx  + time_end_idx + 14]
                        

                    msg_sender = ""

                    send_idx = buffer[idx + search_idx: idx + search_idx + 200].find(send_search)

                    if send_idx != -1:
                        send_end_idx = buffer[search_idx + send_idx: search_idx + send_idx + 60].find(end_search)
                        
                        if send_end_idx != -1:
                            msg_sender = buffer[search_idx + send_idx: search_idx + send_idx  + send_end_idx + 14]

                    yield proc, map.start + idx, msg_time + msg_sender + msg                
                   
                    idx = idx + 5
                    msg_idx = buffer[idx:].find(msg_search)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                          ("Name", "20"),
                          ("Start", "[addrpad]"),
                          ("Size", "8"),
                          ("Path", "")])

        for (proc, start, msg) in data:
            fname = "Adium.{0}.{1:x}.txt".format(proc.p_pid, start)
            file_path = os.path.join(self._config.DUMP_DIR, fname)            

            fd = open(file_path, "wb+")
            fd.write(msg)
            fd.close()

            self.table_row(outfd, 
                           str(proc.p_pid), 
                           proc.p_comm, 
                           start,
                           len(msg),
                           file_path)



