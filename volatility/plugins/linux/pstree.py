# This file is part of Volatility.
# Copyright (C) 2007-2013 Volatility Foundation
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
"""

import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers.basic import Address
from volatility.renderers import TreeGrid
from collections import OrderedDict

class linux_pstree(linux_pslist.linux_pslist):
    '''Shows the parent/child relationship between processes'''

    def __init__(self, *args, **kwargs):
        self.procs = {}
        linux_pslist.linux_pslist.__init__(self, *args, **kwargs)

    def unified_output(self, data):
        return TreeGrid([("Offset",Address),
                        ("Name",str),
                        ("Level",str),
                         ("Pid",int),
                         ("Ppid",int),
                            ("Uid", int),
                            ("Gid",int),
                            ("Euid",int)],
                        self.generator(data))

    def generator(self, data):
        self.procs = OrderedDict()
        for task in data:
            self.recurse_task(task, 0, 0,self.procs)
        
        for offset,name,level,pid,ppid,uid,euid,gid in self.procs.values():
            if offset:
                yield(0,[Address(offset),
                         str(name),
                         str(level),
                         int(pid),
                         int(ppid),
                         int(uid),
                         int(gid),
                         int(euid)])

    def recurse_task(self,task,ppid,level,procs):
        """
        Fill a dictionnary with all the children of a given task(including itself)
        :param task: task that we want to get the children from
        :param ppid: pid of the parent task
        :param level: depth from the root task
        :param procs: dictionnary that we fill
        """
        if not procs.has_key(task.pid.v()):
            if task.mm:
                proc_name = task.comm
            else:
                proc_name = "[" + task.comm + "]"
            procs[task.pid.v()] = (task.obj_offset,proc_name,"." * level + proc_name,task.pid,ppid,task.uid,task.euid,task.gid)
            for child in task.children.list_of_type("task_struct", "sibling"):
                self.recurse_task(child,task.pid, level + 1,procs)

    def render_text(self, outfd, data):
        self.procs = OrderedDict()
        outfd.write("{0:20s} {1:15s} {2:15s}\n".format("Name", "Pid", "Uid"))
        for task in data:
            self.recurse_task(task, 0, 0, self.procs)
        
        for offset,_,proc_name,pid,_,uid,_,_ in self.procs.values():
            if offset:
                outfd.write("{0:20s} {1:15s} {2:15s}\n".format(proc_name, str(pid), str(uid or '')))    

