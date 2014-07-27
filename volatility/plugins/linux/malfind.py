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
import volatility.utils as utils
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_malfind(linux_pslist.linux_pslist):
    """Looks for suspicious process mappings"""

    def render_text(self, outfd, data):
        for task in data:
            proc_as = task.get_process_address_space()

            for vma in task.get_proc_maps():

                if vma.is_suspicious():
                    fname = vma.vm_name(task)
                    if fname == "[vdso]":
                        continue
                   
                    prots = vma.protection()
                    flags = vma.flags()

                    content = proc_as.zread(vma.vm_start, 64)

                    outfd.write("Process: {0} Pid: {1} Address: {2:#x} File: {3}\n".format(
                        task.comm, task.pid, vma.vm_start, fname))

                    outfd.write("Protection: {0}\n".format(prots))

                    outfd.write("Flags: {0}\n".format(str(flags)))
                    outfd.write("\n")

                    outfd.write("{0}\n".format("\n".join(
                        ["{0:#010x}  {1:<48}  {2}".format(vma.vm_start + o, h, ''.join(c))
                        for o, h, c in utils.Hexdump(content)
                        ])))

                    outfd.write("\n")
                    outfd.write("\n".join(
                        ["{0:#x} {1:<16} {2}".format(o, h, i)
                        for o, i, h in malfind.Disassemble(content, vma.vm_start)
                        ]))
                
                    outfd.write("\n\n")

       


 
