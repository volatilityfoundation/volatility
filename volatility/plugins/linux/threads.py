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
@author: Edwin Smulders
@license: GNU General Public License 2.0 or later
@contact: mail@edwinsmulders.eu
"""

import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.common as linux_common
import volatility.obj as obj

class linux_threads(linux_pslist.linux_pslist):
    """ Prints threads of processes """
    
    def render_text(self, outfd, data):
        for task in data:
            outfd.write("\nProcess Name: {}\nProcess ID: {}\n".format(task.comm, task.tgid))
            self.table_header(outfd, [('Thread PID', '13'), ('Thread Name', '16')])
            for thread in task.threads():
                self.table_row(outfd, str(thread.pid), thread.comm)



