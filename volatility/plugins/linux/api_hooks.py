# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_api_hooks(linux_pslist.linux_pslist):
    """Search for hooked apis"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        procs = linux_pslist.linux_pslist(self._config).calculate()

        for task in procs:
            pass            


    def render_text(self, outfd, data):
        for blah in data:
            pass

        '''
        self.table_header(outfd, [("Pid", "8"),
                                  ("Name", "16"),
                                  ("Start", "#018x"),
                                  ("End",   "#018x"),
                                  ("Flags", "6"),
                                  ("File Path", "50"),                    
                                 ]) 

        for task, proc_as, vma in data:
            if vma.vm_file: 
                fname = linux_common.get_path(task, vma.vm_file)
            elif vma.vm_start <= task.mm.start_brk and vma.vm_end >= task.mm.brk:
                fname = "[heap]"
            elif vma.vm_start <= task.mm.start_stack and vma.vm_end >= task.mm.start_stack:
                fname = "[stack]"
            elif vma.vm_start == vma.vm_mm.context.vdso:
                continue
            else:
                fname = ""
        
            self.table_row(outfd, 
                task.pid, 
                str(task.comm),
                vma.vm_start,
                vma.vm_end,
                str(vma.vm_flags),
                fname)
        '''

