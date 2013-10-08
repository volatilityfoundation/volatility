# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import volatility.obj as obj
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.pidhashtable as linux_pidhashtable
import volatility.plugins.linux.pslist_cache as linux_pslist_cache
import volatility.plugins.linux.common as linux_common

#based off the windows version from mhl
#
#INFO:
#    'pslist' does not get threads
#    'pid_hash' does
#    'kmem_cache' does
#    'runqueue' does

class linux_psxview(linux_common.AbstractLinuxCommand):
    "Find hidden processes with various process listings"

    def get_pslist(self):
        return [x.obj_offset for x in linux_pslist.linux_pslist(self._config).calculate()]

    def get_pid_hash(self):
        return [x.obj_offset for x in linux_pidhashtable.linux_pidhashtable(self._config).calculate()]

    def get_kmem_cache(self):
        return [x.obj_offset for x in linux_pslist_cache.linux_pslist_cache(self._config).calculate()]

    def calculate(self):
        linux_common.set_plugin_members(self)

        ps_sources = {}

        # The keys are names of process sources
        # The values are the virtual offset of the task_struct

        ps_sources['pslist'] = self.get_pslist()
        ps_sources['pid_hash'] = self.get_pid_hash()
        ps_sources['kmem_cache'] = self.get_kmem_cache()

        # FUTURE
        # ps_sources['run_queue']  = 

        # Build a list of offsets from all sources
        seen_offsets = []
        for source in ps_sources:

            tasks = ps_sources[source]

            for offset in tasks:

                if offset not in seen_offsets:
                    seen_offsets.append(offset)
                    yield offset, obj.Object("task_struct", offset = offset, vm = self.addr_space), ps_sources

    def render_text(self, outfd, data):

        self.table_header(outfd, [('Offset(V)', '[addrpad]'),
                                  ('Name', '<20'),
                                  ('PID', '>6'),
                                  ('pslist', '5'),
                                  ('pid_hash', '5'),
                                  ('kmem_cache', '5'),
                                  ])

        for offset, process, ps_sources in data:
            self.table_row(outfd,
                offset,
                process.comm,
                process.pid,
                str(ps_sources['pslist'].__contains__(offset)),
                str(ps_sources['pid_hash'].__contains__(offset)),
                str(ps_sources['kmem_cache'].__contains__(offset))
                )
