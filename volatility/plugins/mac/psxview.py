# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
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

import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.mac.common as common
import volatility.plugins.mac.pslist as pslist
import volatility.plugins.mac.pid_hash_table as pid_hash_table
import volatility.plugins.mac.pgrp_hash_table as pgrp_hash_table
import volatility.plugins.mac.session_hash_table as session_hash_table
import volatility.plugins.mac.pstasks as pstasks
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class mac_psxview(common.AbstractMacCommand):
    "Find hidden processes with various process listings"

    def _get_pslist(self):
        return [p.v() for p in pslist.mac_pslist(self._config).calculate()]

    def _get_parent_pointers(self):
        return [p.p_pptr.v() for p in pslist.mac_pslist(self._config).calculate()]

    def _get_pid_hash_table(self):
        return [p.v() for p in pid_hash_table.mac_pid_hash_table(self._config).calculate()]
    
    def _get_pgrp_hash_table(self):
        return [p.v() for p in pgrp_hash_table.mac_pgrp_hash_table(self._config).calculate()]
 
    def _get_session_hash_table(self):
        return [s.s_leader.v() for s in session_hash_table.mac_list_sessions(self._config).calculate() if s.s_leader.is_valid()]
    
    def _get_procs_from_tasks(self):
        return [p.v() for p in pstasks.mac_tasks(self._config).calculate()]       

    def calculate(self):
        common.set_plugin_members(self)

        ps_sources = {}
        
        ps_sources['pslist']   = self._get_pslist()
        ps_sources['parents']  = self._get_parent_pointers()
        ps_sources['pid_hash'] = self._get_pid_hash_table()
        ps_sources['pgrp_hash_table']    = self._get_pgrp_hash_table() 
        ps_sources['session_hash_table'] = self._get_session_hash_table() 
        ps_sources['procs_from_tasks']   = self._get_procs_from_tasks()

        # Build a list of offsets from all sources
        seen_offsets = []
        for source in ps_sources:
            tasks = ps_sources[source]

            for offset in tasks:
                if offset not in seen_offsets:
                    seen_offsets.append(offset)
                    yield offset, obj.Object("proc", offset = offset, vm = self.addr_space), ps_sources
                    
    def unified_output(self, data):
        return TreeGrid([("Offset(V)", Address),
                                  ("Name", str),
                                  ("PID", int),
                                  ("pslist", str ),
                                  ("parents", str),
                                  ("pid_hash", str),
                                  ("pgrp_hash_table", str),
                                  ("session leaders", str),
                                  ("task processes", str),
                                  ], self.generator(data))
                                  
    def generator(self, data):
        for offset, process, ps_sources in data:
            yield (0, [
                Address(offset),
                str(process.p_comm),
                int(process.p_pid),
                str(ps_sources['pslist'].__contains__(offset)),
                str(ps_sources['parents'].__contains__(offset)),
                str(ps_sources['pid_hash'].__contains__(offset)),
                str(ps_sources['pgrp_hash_table'].__contains__(offset)),
                str(ps_sources['session_hash_table'].__contains__(offset)),
                str(ps_sources['procs_from_tasks'].__contains__(offset)),
                ])



    def render_text(self, outfd, data):

        self.table_header(outfd, [('Offset(V)', '[addrpad]'),
                                  ('Name', '<20'),
                                  ('PID', '>6'),
                                  ('pslist', '5'),
                                  ('parents', '5'),
                                  ('pid_hash', '5'),
                                  ('pgrp_hash_table', '5'),
                                  ('session leaders', '5'),
                                  ('task processes', '5'),
                                  ])

        for offset, process, ps_sources in data:
            self.table_row(outfd,
                offset,
                process.p_comm,
                str(process.p_pid),
                str(ps_sources['pslist'].__contains__(offset)),
                str(ps_sources['parents'].__contains__(offset)),
                str(ps_sources['pid_hash'].__contains__(offset)),
                str(ps_sources['pgrp_hash_table'].__contains__(offset)),
                str(ps_sources['session_hash_table'].__contains__(offset)),
                str(ps_sources['procs_from_tasks'].__contains__(offset)),
                )
