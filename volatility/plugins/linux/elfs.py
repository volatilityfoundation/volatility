# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2014 CrowdStrike, Inc.
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
@author:       Georg Wicherski
@license:      GNU General Public License 2.0
@contact:      georg@crowdstrike.com
@organization: CrowdStrike, Inc.
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.dump_map as linux_dump_map
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_elfs(linux_pslist.linux_pslist):
    """Find ELF binaries in process mappings"""

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            for elf, elf_start, elf_end, soname, needed in task.elfs():
                yield task, elf, elf_start, elf_end, soname, needed
    
    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                       ("Name", str),
                       ("Start", Address),
                       ("End", Address),
                       ("Path", str),
                       ("Needed", str)],
                        self.generator(data))

    def generator(self, data):
        for task, elf, start, end, soname, needed in data:
            yield (0, [int(task.pid), str(task.comm), Address(start), Address(end), str(soname), ",".join(needed)])
 

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"),
                                  ("Name", "17"),
                                  ("Start", "[addrpad]"),
                                  ("End", "[addrpad]"),
                                  ("Elf Path", "60"),
                                  ("Needed", "")
                                ])
        for task, elf, start, end, soname, needed in data:
            self.table_row(outfd, task.pid, task.comm, start, end, soname, ",".join(needed))

