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
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

#based off the windows version from mhl
#
#INFO:
#    'pslist' does not get threads
#    'pid_hash' does
#    'kmem_cache' does
#    'runqueue' does

class linux_psxview(linux_common.AbstractLinuxCommand):
    "Find hidden processes with various process listings"

    def _get_pslist(self):
        return [x.obj_offset for x in linux_pslist.linux_pslist(self._config).calculate()]

    def _get_pid_hash(self):
        return [x.obj_offset for x in linux_pidhashtable.linux_pidhashtable(self._config).calculate()]

    def _get_kmem_cache(self):
        return [x.obj_offset for x in linux_pslist_cache.linux_pslist_cache(self._config).calculate()]

    def _get_task_parents(self):
        return [x.real_parent.v() for x in linux_pslist.linux_pslist(self._config).calculate()]
    
    def _get_thread_leaders(self):
        return [x.group_leader.v() for x in linux_pidhashtable.linux_pidhashtable(self._config).calculate()]

    def calculate(self):
        linux_common.set_plugin_members(self)

        ps_sources = {}

        # The keys are names of process sources
        # The values are the virtual offset of the task_struct

        ps_sources['pslist']     = self._get_pslist()
        ps_sources['pid_hash']   = self._get_pid_hash()
        ps_sources['kmem_cache'] = self._get_kmem_cache()
        ps_sources['parents']    = self._get_task_parents()
        ps_sources['thread_leaders'] = self._get_thread_leaders()

        # Build a list of offsets from all sources
        seen_offsets = []
        for source in ps_sources:

            tasks = ps_sources[source]

            for offset in tasks:

                if offset not in seen_offsets:
                    seen_offsets.append(offset)
                    yield offset, obj.Object("task_struct", offset = offset, vm = self.addr_space), ps_sources

    def unified_output(self, data):
        return TreeGrid([("Offset(V)", Address),
                       ("Name", str),
                       ("PID", int),
                       ("pslist", str),
                       ("pid_hash", str),
                       ("kmem_cache", str),
                       ("parents", str),
                       ("leaders", str)],
                        self.generator(data))

    def generator(self, data):
        for offset, process, ps_sources in data:
            yield(0, [Address(offset),
                str(process.comm),
                int(process.pid),
                str(ps_sources['pslist'].__contains__(offset)),
                str(ps_sources['pid_hash'].__contains__(offset)),
                str(ps_sources['kmem_cache'].__contains__(offset)),
                str(ps_sources['parents'].__contains__(offset)),
                str(ps_sources['thread_leaders'].__contains__(offset))])

    def render_text(self, outfd, data):
        self.table_header(outfd, [('Offset(V)', '[addrpad]'),
                                  ('Name', '<20'),
                                  ('PID', '>6'),
                                  ('pslist', '5'),
                                  ('pid_hash', '5'),
                                  ('kmem_cache', '5'),
                                  ('parents', '5'),
                                  ('leaders', '5'),
                                  ])

        for offset, process, ps_sources in data:
            self.table_row(outfd,
                offset,
                process.comm,
                process.pid,
                str(ps_sources['pslist'].__contains__(offset)),
                str(ps_sources['pid_hash'].__contains__(offset)),
                str(ps_sources['kmem_cache'].__contains__(offset)),
                str(ps_sources['parents'].__contains__(offset)),
                str(ps_sources['thread_leaders'].__contains__(offset)),
                )
