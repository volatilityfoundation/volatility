# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
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
@organization: 
"""
import volatility.obj as obj
import volatility.plugins.mac.common as common
import volatility.plugins.mac.pstasks as pstasks

class mac_kevents(common.AbstractMacCommand):
    """ Show parent/child relationship of processes """

    def _walk_karray(self, address, count):
        arr = obj.Object(theType = "Array", targetType = "klist", offset = address, vm = self.addr_space, count = count) 

        for klist in arr:
                kn = klist.slh_first

                while kn.is_valid():
                    yield kn
 
                    kn = kn.kn_link.sle_next
 
    def calculate(self):
        common.set_plugin_members(self)
   
        for task in pstasks.mac_tasks(self._config).calculate():
            fdp = task.p_fd
    
            # for (i = 0; i < fdp->fd_knlistsize; i++) {
            #    kn = SLIST_FIRST(&fdp->fd_knlist[i]);
            for kn in self._walk_karray(fdp.fd_knlist, fdp.fd_knlistsize):
                yield task, kn
            
            # if (fdp->fd_knhashmask != 0) {
            #    for (i = 0; i < (int)fdp->fd_knhashmask + 1; i++) {
            #        kn = SLIST_FIRST(&fdp->fd_knhash[i]);
            mask = fdp.fd_knhashmask             
            if mask != 0:
                for kn in self._walk_karray(fdp.fd_knhash, mask + 1):
                    yield task, kn


            kn = task.p_klist.slh_first
            while kn.is_valid():
                
                yield task, kn

                kn = kn.kn_link.sle_next

    def _get_flags(self, fflags, filters): 
        context = ""

        if fflags != 0:
            for (flag, idx) in filters:
                if fflags & idx == idx:
                    context = context + flag + ", "   

            if len(context) > 2 and context[-2:] == ", ":
                context = context[:-2]                     

        return context

    def render_text(self, outfd, data):
        event_types = ["INVALID EVENT", "EVFILT_READ", "EVFILT_WRITE", "EVFILT_AIO", "EVFILT_VNODE", "EVFILT_PROC", "EVFILT_SIGNAL"]
        event_types = event_types + ["EVFILT_TIMER", "EVFILT_MACHPORT", "EVFILT_FS", "EVFILT_USER", "INVALID EVENT", "EVFILT_VM"]
                
        vnode_filt = [("NOTE_DELETE", 1), ("NOTE_WRITE", 2), ("NOTE_EXTEND", 4), ("NOTE_ATTRIB", 8)]
        vnode_filt = vnode_filt + [("NOTE_LINK", 0x10), ("NOTE_RENAME", 0x20), ("NOTE_REVOKE", 0x40)]          
 
        proc_filt  = [("NOTE_EXIT", 0x80000000), ("NOTE_EXITSTATUS", 0x04000000), ("NOTE_FORK", 0x40000000)]
        proc_filt  = proc_filt + [("NOTE_EXEC", 0x20000000), ("NOTE_SIGNAL", 0x08000000), ("NOTE_REAP", 0x10000000)]

        time_filt = [("NOTE_SECONDS", 1), ("NOTE_USECONDS", 2), ("NOTE_NSECONDS", 4), ("NOTE_ABSOLUTE", 8)]

        self.table_header(outfd, [("Offset", "[addrpad]"),
                          ("Name", "20"),
                          ("Pid", "8"),
                          ("Ident", "6"),
                          ("Filter", "20"),
                          ("Context", ""),])

        for task, kn in data:
            filt_idx = kn.kn_kevent.filter * -1
            if 0 < filt_idx < len(event_types):
                fname = event_types[filt_idx]
            else:
                continue

            context = ""    
            fflags  = kn.kn_sfflags

            # EVFILT_VNODE
            if filt_idx == 4:
                context = self._get_flags(fflags, vnode_filt)
 
            # EVFILT_PROC
            elif filt_idx == 5:
                context = self._get_flags(fflags, proc_filt) 

            elif filt_idx == 7:
                context = self._get_flags(fflags, time_filt) 

            self.table_row(outfd, kn.v(), str(task.p_comm), task.p_pid, kn.kn_kevent.ident, fname, context)   







