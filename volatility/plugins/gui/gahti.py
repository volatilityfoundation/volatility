# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
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

import volatility.utils as utils
import volatility.plugins.gui.constants as consts
import volatility.plugins.gui.sessions as sessions

class Gahti(sessions.Sessions):
    """Dump the USER handle type information"""

    def render_text(self, outfd, data):

        profile = utils.load_as(self._config).profile

        # Get the OS version being analyzed 
        version = (profile.metadata.get('major', 0),
                   profile.metadata.get('minor', 0))

        # Choose which USER handle enum to use 
        if version >= (6, 1):
            handle_types = consts.HANDLE_TYPE_ENUM_SEVEN
        else:
            handle_types = consts.HANDLE_TYPE_ENUM

        self.table_header(outfd,
                         [("Session", "8"),
                          ("Type", "20"),
                          ("Tag", "8"),
                          ("fnDestroy", "[addrpad]"),
                          ("Flags", ""),
                         ])

        for session in data:
            gahti = session.find_gahti()
            if gahti:
                for i, h in handle_types.items():
                    self.table_row(outfd,
                                    session.SessionId,
                                    h,
                                    gahti.types[i].dwAllocTag,
                                    gahti.types[i].fnDestroy,
                                    gahti.types[i].bObjectCreateFlags)
