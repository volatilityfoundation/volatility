# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
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
#

import volatility.commands as commands
import volatility.utils as utils
import volatility.plugins.gui.sessions as sessions

class GDITimers(commands.Command, sessions.SessionsMixin):
    """Print installed GDI timers and callbacks"""

    def calculate(self):
        kernel_as = utils.load_as(self._config)

        for session in self.session_spaces(kernel_as):

            shared_info = session.find_shared_info()
            if not shared_info:
                continue

            filters = [lambda x : str(x.bType) == "TYPE_TIMER"]

            for handle in shared_info.handles(filters):
                timer = handle.reference_object()
                yield session, handle, timer

    def render_text(self, outfd, data):

        self.table_header(outfd,
                         [("Sess", "^6"),
                          ("Handle", "[addr]"),
                          ("Object", "[addrpad]"),
                          ("Thread", "8"),
                          ("Process", "20"),
                          ("nID", "[addr]"),
                          ("Rate(ms)", "10"),
                          ("Countdown(ms)", "10"),
                          ("Func", "[addrpad]"),
                         ])

        for session, handle, timer in data:

            process = "{0}:{1}".format(
                timer.pti.ppi.Process.ImageFileName,
                timer.pti.pEThread.Cid.UniqueProcess
                )

            self.table_row(outfd,
                            session.SessionId,
                            handle.phead.h,
                            timer.obj_offset,
                            timer.pti.pEThread.Cid.UniqueThread,
                            process,
                            timer.nID,
                            timer.cmsRate,
                            timer.cmsCountdown,
                            timer.pfn)
