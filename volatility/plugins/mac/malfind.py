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
import volatility.plugins.mac.common as mac_common
import volatility.plugins.mac.pstasks as mac_pstasks

class mac_malfind(mac_pstasks.mac_tasks):
    """Looks for suspicious process mappings"""

    def render_text(self, outfd, data):
        for task in data:
            proc_as = task.get_process_address_space()

            bit_string = str(task.task.map.pmap.pm_task_map or '')[9:]

            if bit_string == "64BIT":
                bits = '64bit'
            else:
                bits = '32bit'

            for map in task.get_proc_maps():
                if map.is_suspicious():
                    fname = map.get_path()                    
                    prots = map.get_perms()

                    content = proc_as.zread(map.start, 64)

                    outfd.write("Process: {0} Pid: {1} Address: {2:#x} File: {3}\n".format(
                        task.p_comm, task.p_pid, map.start, fname))

                    outfd.write("Protection: {0}\n".format(prots))

                    outfd.write("\n")

                    outfd.write("{0}\n".format("\n".join(
                        ["{0:#010x}  {1:<48}  {2}".format(map.start + o, h, ''.join(c))
                        for o, h, c in utils.Hexdump(content)
                        ])))

                    outfd.write("\n")
                    outfd.write("\n".join(
                        ["{0:#x} {1:<16} {2}".format(o, h, i)
                        for o, i, h in malfind.Disassemble(content, map.start, bits = bits)
                        ]))
                
                    outfd.write("\n\n")

       


 
