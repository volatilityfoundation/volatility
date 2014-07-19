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
import volatility.plugins.mac.common  as mac_common
import volatility.plugins.mac.pstasks as mac_tasks

class mac_bash_env(mac_tasks.mac_tasks):
    """Recover bash's environment variables"""

    def calculate(self):
        mac_common.set_plugin_members(self)
    
        tasks = mac_tasks.mac_tasks(self._config).calculate()
        
        for task in tasks:
            proc_as = task.get_process_address_space()
            
            # In cases when mm is an invalid pointer 
            if not proc_as:
                continue
            
            # Are we dealing with 32 or 64-bit pointers
            bit_string = str(task.task.map.pmap.pm_task_map or '')[9:]
            if bit_string.find("64BIT") == -1:
                pack_format = "<I"
                addr_sz = 4
                addr_type = "unsigned int"
            else:
                pack_format = "<Q"
                addr_sz = 8
                addr_type = "unsigned long long"
     
            procvars = []
            for mapping in task.get_proc_maps():
                if not str(mapping.get_perms()) == "rw-" or mapping.get_path().find("bash") == -1:
                    continue

                env_start = 0
                for off in range(mapping.links.start, mapping.links.end):
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

                envars = obj.Object(theType="Array", targetType=addr_type, vm=proc_as, offset=env_start, count=256)
                for var in envars:
                    if var:
                        sizes = [8, 16, 32, 64, 128, 256, 384, 512, 1024, 2048, 4096]
                        good_varstr = None

                        for size in sizes:
                            varstr = proc_as.read(var, size)
                            if not varstr:
                                continue

                            eqidx = varstr.find("=")
                            idx = varstr.find("\x00")

                            if idx == -1 or eqidx == -1 or idx < eqidx:
                                continue
                        
                            good_varstr = varstr
                            break
                    
                        if good_varstr:        
                            good_varstr = good_varstr[:idx]
                            procvars.append(good_varstr) 

                yield task, " ".join(procvars)

                break

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("Vars", "")])
                                    
        for task, vars in data:
            self.table_row(outfd, task.p_pid, task.p_comm, vars)

