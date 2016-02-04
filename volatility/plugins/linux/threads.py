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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

"""
@author: Edwin Smulders
@license: GNU General Public License 2.0 or later
@contact: mail@edwinsmulders.eu
"""

import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers.basic import Address
from volatility.renderers import TreeGrid

class linux_threads(linux_pslist.linux_pslist):
    """ Prints threads of processes """

    def unified_output(self, data):
        return TreeGrid([("Offset",Address),
                        ("NameProc",str),
                         ("TGID",int),
                         ("ThreadPid",str),
                            ("ThreadName", str),
                        ("thread_offset",Address),
                            ("Addr_limit",Address),
                            ("uid_cred",int),
                            ("gid_cred",int),
                            ("euid_cred",int)
                        ],
                        self.generator(data))

    def generator(self, data):

        for task in data:
            euidcred = task.euid
            uidcred = task.uid
            gidcred = task.gid
            for thread in task.threads():
                addr_limit = self.get_addr_limit(thread)
                yield(0,[Address(task.obj_offset),
                         str(task.comm),
                         int(task.tgid),
                         str(thread.pid),
                         str(thread.comm),
                         Address(thread.obj_offset),
                         Address(addr_limit),
                         int(uidcred),
                         int(gidcred),
                         int(euidcred)
                ])

    def get_addr_limit(self,thread, addrvar_offset = 8 ):
        """
        Here we read the addr_limit variable of a thread by reading at the offset of the thread plus
        the offset of the addr_limit variable inside the thread_info
        :param thread: thread from which we want the information
        :param addrvar_offset: offset of the addr_limit var in the thread_info
        :return: the addr_limit
        """
        addr_space = thread.get_process_address_space()
        offset = thread.obj_offset + addrvar_offset
        return addr_space.read_long_phys(offset)

    def render_text(self, outfd, data):
        for task in data:
            outfd.write("\nProcess Name: {}\nProcess ID: {}\n".format(task.comm, task.tgid))
            self.table_header(outfd, [('Thread PID', '13'), ('Thread Name', '16')])
            for thread in task.threads():
                self.table_row(outfd, str(thread.pid), thread.comm)

    


