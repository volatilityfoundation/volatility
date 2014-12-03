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

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.ifconfig as linux_ifconfig
import volatility.plugins.linux.pslist as linux_pslist
import volatility.debug as debug
import volatility.obj as obj

class linux_list_raw(linux_common.AbstractLinuxCommand):
    """List applications with promiscuous sockets"""

    def __init__(self, config, *args, **kwargs):
        self.fd_cache = {}
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

    def _SOCK_INODE(self, sk):
        backsize = self.profile.get_obj_size("socket")
        addr = sk + backsize

        return obj.Object('inode', offset = addr, vm = self.addr_space) 

    def _walk_net_spaces(self):
        offset = self.addr_space.profile.get_obj_offset("sock_common", "skc_node")
        
        nslist_addr = self.addr_space.profile.get_symbol("net_namespace_list")
        nethead = obj.Object("list_head", offset = nslist_addr, vm = self.addr_space)
            
        for net in nethead.list_of_type("net", "list"):
            node = net.packet.sklist.first.dereference().v()
            
            sk = obj.Object("sock", offset = node - offset, vm = self.addr_space)

            while sk.is_valid():
                inode = self._SOCK_INODE(sk.sk_socket)

                ino = inode

                yield ino

                sk = obj.Object("sock", offset = sk.sk_node.next - offset, vm = self.addr_space)

    def _fill_cache(self):
        for task in linux_pslist.linux_pslist(self._config).calculate():
            for filp, fd in task.lsof():
                filepath = linux_common.get_path(task, filp)
                if type(filepath) == str and filepath.find("socket:[") != -1:
                    to_add = filp.dentry.d_inode.i_ino.v()
                    self.fd_cache[to_add] = [task, filp, fd, filepath]
   
    def _find_proc_for_inode(self, inode):
        if self.fd_cache == {}:
            self._fill_cache()
        
        inum = inode.i_ino.v()

        if inum in self.fd_cache:
            (task, filp, fd, filepath) = self.fd_cache[inum]
        else:
            (task, filp, fd, filepat)  = (None, None, None, None)

        return (task, fd, inum)

    def __walk_hlist_node(self, node):    
        seen = set()

        offset = self.addr_space.profile.get_obj_offset("sock_common", "skc_node")

        nxt = node.next.dereference()
        
        while nxt.is_valid() and nxt.obj_offset not in seen:
            ## Instantiate the object
            item = obj.Object(obj_type, offset = nxt.obj_offset - offset, vm = self.addr_space)

            seen.add(nxt.obj_offset)

            yield item

            nxt = nxt.next.dereference()

    def _walk_packet_sklist(self):
        sklist_addr = self.addr_space.profile.get_symbol("packet_sklist")
    
        sklist = obj.Object("hlist_head", offset = sklist_addr, vm = self.addr_space)

        for sk in self.__walk_hlist_node(sklist.first):
            yield self._SOCK_INODE(sk.sk_socket)

    def calculate(self):
        linux_common.set_plugin_members(self)

        sym_addr = self.addr_space.profile.get_symbol("packet_sklist") 

        # old kernels before namespaces
        if sym_addr:
            for inode in self._walk_packet_sklist():
                yield self._find_proc_for_inode(inode) 
        else:
            for inode in self._walk_net_spaces():
                yield self._find_proc_for_inode(inode)
            
    def render_text(self, outfd, data):

        self.table_header(outfd, [("Process", "16"),
                                  ("PID", "6"),
                                  ("File Descriptor", "5"),
                                  ("Inode", "18"),
                                 ])

        for (task, fd, inum) in data:
            if task:
                self.table_row(outfd, task.comm, task.pid, fd, inum)
