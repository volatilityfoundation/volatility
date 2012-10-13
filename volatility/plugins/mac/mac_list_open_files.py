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
import mac_pslist
import mac_common

'''
  121 /* file types */
  122 typedef enum {
  123         DTYPE_VNODE     = 1,    /* file */
  124         DTYPE_SOCKET,           /* communications endpoint */
  125         DTYPE_PSXSHM,           /* POSIX Shared memory */
  126         DTYPE_PSXSEM,           /* POSIX Semaphores */
  127         DTYPE_KQUEUE,           /* kqueue */
  128         DTYPE_PIPE,             /* pipe */
  129         DTYPE_FSEVENTS          /* fsevents */
  130 } file_type_t;
'''

class mac_list_open_files(mac_pslist.mac_pslist):

    def calculate(self):

        procs = mac_pslist.mac_pslist.calculate(self)

        for proc in procs:
    
            fdinfo = proc.p_fd 

            files  = fdinfo.fd_ofiles
            max    = fdinfo.fd_lastfile

            fds = obj.Object(theType = 'Array', offset = files.v(), vm = self.addr_space, targetType = 'Pointer', count = max)

            for i in xrange(0, max):

                if not fds[i]:
                    continue

                f    = obj.Object("fileproc", offset=fds[i], vm=self.addr_space)
                
                data_ptr  = f.f_fglob.fg_data

                data_type = f.f_fglob.fg_type

                yield (data_ptr, data_type, i)                
 
    def render_text(self, outfd, data):
        
        for (data_ptr, data_type, i) in data:

            # file
            if data_type == 1:
                
                vnode = obj.Object("vnode", offset=data_ptr.v(), vm=self.addr_space)

                path  = self.calc_full_path(vnode)

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
            files    = []

            self.do_calc_path(elements, vnode, vnode.v_name)

            elements.reverse()

            for e in elements:
                files.append(mac_common.get_string(e, self.addr_space))

            ret = "/".join(files)                

            if ret:
                ret = "/" + ret

        return ret


                





