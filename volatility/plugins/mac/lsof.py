# Volatility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.plugins.mac.pstasks as pstasks
import volatility.plugins.mac.common as common

class mac_lsof(pstasks.mac_tasks):
    """ Lists per-process opened files """
    def calculate(self):
        common.set_plugin_members(self)

        procs = pstasks.mac_tasks(self._config).calculate()

        for proc in procs:
            fds = obj.Object('Array', offset = proc.p_fd.fd_ofiles, vm = self.addr_space, targetType = 'Pointer', count = proc.p_fd.fd_lastfile)

            for i, fd in enumerate(fds):
                f = fd.dereference_as("fileproc")
                if f:
                    ## FIXME after 2.3 replace this explicit int field with the following line:
                    ##    if str(f.f_fglob.fg_type) == 'DTYPE_VNODE':
                    ## Its not needed for profiles generated with convert.py after r3290 
                    fg_type = obj.Object("int", f.f_fglob.fg_type.obj_offset, vm = self.addr_space)
                    if fg_type == 1: # VNODE
                        vnode = f.f_fglob.fg_data.dereference_as("vnode")
                        path = vnode.full_path()
                    else:
                        path = ""
                                        
                    yield proc, i, f, path
 
    def render_text(self, outfd, data):
        self.table_header(outfd, [("PID","8"),
                                  ("File Descriptor", "6"),
                                  ("File Path", ""),
                                 ])
 
        for proc, i, f, path in data:
            if path:
                self.table_row(outfd, proc.p_pid, i, path)

   
