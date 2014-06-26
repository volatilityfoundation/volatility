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

import struct
from operator import attrgetter
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.linux.common  as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_bash_env(linux_pslist.linux_pslist):
    """Recover bash's environment variables"""

    def calculate(self):
        linux_common.set_plugin_members(self)
    
        tasks = linux_pslist.linux_pslist(self._config).calculate()
        
        # Are we dealing with 32 or 64-bit pointers
        if self.addr_space.profile.metadata.get('memory_model', '32bit') == '32bit':
            pack_format = "<I"
            addr_sz = 4
        else:
            pack_format = "<Q"
            addr_sz = 8
            
        for task in tasks:
            proc_as = task.get_process_address_space()
            
            # In cases when mm is an invalid pointer 
            if not proc_as:
                continue

            procvars = []
            for vma in task.get_proc_maps():
                if not (vma.vm_file and str(vma.vm_flags) == "rw-" and linux_common.get_path(task, vma.vm_file).find("bash") != -1):
                    continue

                env_start = 0
                for off in range(vma.vm_start, vma.vm_end):
                    # check the first index
                    addrstr = proc_as.read(off, addr_sz)
                    if not addrstr or len(addrstr) != addr_sz:
                        continue
                    addr = struct.unpack(pack_format, addrstr)[0]
                    # check first idx...
                    if addr:
                        firstaddrstr = proc_as.read(addr, addr_sz)
                        if not firstaddrstr or len(firstaddrstr) != addr_sz:
                            continue
                        firstaddr = struct.unpack(pack_format, firstaddrstr)[0]
                        buf = proc_as.read(firstaddr, 64)
                        if not buf:
                            continue
                        eqidx = buf.find("=")
                        if eqidx > 0:
                            nullidx = buf.find("\x00")
                            # single char name, =
                            if nullidx >= eqidx:
                                env_start = addr

                if env_start == 0:
                    continue

                envars = obj.Object(theType="Array", targetType="Pointer", vm=proc_as, offset=env_start, count=256)
                for var in envars:
                    if var:
                        varstr = proc_as.read(var, 1600)
                        eqidx = varstr.find("=")
                        idx = varstr.find("\x00")

                        if idx == -1 or eqidx == -1 or idx < eqidx:
                            break

                        varstr = varstr[:idx]

                        procvars.append(varstr) 

                yield task, " ".join(procvars)

                break

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Vars", "")])
                                    
        for task, vars in data:
            self.table_row(outfd, task.pid, task.comm, vars)

