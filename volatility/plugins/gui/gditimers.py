# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
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

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.plugins.gui.sessions as sessions

class GDITimers(common.AbstractWindowsCommand, sessions.SessionsMixin):
    """Print installed GDI timers and callbacks"""

    @staticmethod
    def is_valid_profile(profile):
        version = (profile.metadata.get('major', 0), 
                   profile.metadata.get('minor', 0))

        return (profile.metadata.get('os', '') == 'windows' and
                version < (6, 2))

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

            # Get the process info from the object handle header if 
            # available, otherwise from the timer object itself. 
            p = handle.Process or timer.pti.ppi.Process
            process = "{0}:{1}".format(p.ImageFileName, p.UniqueProcessId)

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
