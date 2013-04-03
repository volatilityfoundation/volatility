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

        procs = pstasks.mac_tasks.calculate(self)

        for proc in procs:
            fds = obj.Object('Array', offset = proc.p_fd.fd_ofiles, vm = self.addr_space, targetType = 'Pointer', count = proc.p_fd.fd_lastfile)

            for i, fd in enumerate(fds):
                f = fd.dereference_as("fileproc")
                if f:
                    yield i, f              
 
    def render_text(self, outfd, data):
        
        for i, f in data:
            ## FIXME after 2.3 replace this explicit int field with the following line:
            ##    if str(f.f_fglob.fg_type) == 'DTYPE_VNODE':
            ## Its not needed for profiles generated with convert.py after r3290 
            fg_type = obj.Object("int", f.f_fglob.fg_type.obj_offset, vm = self.addr_space)
            if fg_type == 1: # VNODE
                vnode = f.f_fglob.fg_data.dereference_as("vnode")
                path = self.calc_full_path(vnode)
                outfd.write("{0:d} -> {1:s}\n".format(i, path))

    def do_calc_path(self, ret, vnode, vname):

        if vnode == None:
            return 

        if vname:
            ret.append(vname)

        if vnode.v_flag.v() & 0x000001 != 0 and vnode.v_mount.v() != 0: 
            if vnode.v_mount.mnt_vnodecovered.v() != 0:
                self.do_calc_path(ret, vnode.v_mount.mnt_vnodecovered, vnode.v_mount.mnt_vnodecovered.v_name)
        else:  
            self.do_calc_path(ret, vnode.v_parent, vnode.v_parent.v_name)
                
    def calc_full_path(self, vnode):
    
        if vnode.v_flag.v() & 0x000001 != 0 and vnode.v_mount.v() != 0 and vnode.v_mount.mnt_flag.v() & 0x00004000 != 0:
            ret = "/"
        else: 
            elements = []
            files = []

            self.do_calc_path(elements, vnode, vnode.v_name)
            elements.reverse()

            for e in elements:
                files.append(str(e.dereference()))

            ret = "/".join(files)                
            if ret:
                ret = "/" + ret

        return ret
