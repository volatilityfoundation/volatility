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

import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.plugins.gui.sessions as sessions
import volatility.plugins.gui.windowstations as windowstations
import volatility.plugins.gui.constants as consts

class Clipboard(common.AbstractWindowsCommand, sessions.SessionsMixin):
    """Extract the contents of the windows clipboard"""

    def calculate(self):
        kernel_space = utils.load_as(self._config)

        # Dictionary of MM_SESSION_SPACEs by ID
        sesses = dict((int(session.SessionId), session)
            for session in self.session_spaces(kernel_space)
                )

        # Dictionary of session USER objects by handle
        session_handles = {}

        # If various objects cannot be found or associated, 
        # we'll return none objects
        e0 = obj.NoneObject("Unknown tagCLIPDATA")
        e1 = obj.NoneObject("Unknown tagWINDOWSTATION")
        e2 = obj.NoneObject("Unknown tagCLIP")

        # Handle type filter 
        filters = [lambda x : str(x.bType) == "TYPE_CLIPDATA"]

        # Load tagCLIPDATA handles from all sessions 
        for sid, session in sesses.items():
            handles = {}
            shared_info = session.find_shared_info()
            if not shared_info:
                debug.debug("No shared info for session {0}".format(sid))
                continue
            for handle in shared_info.handles(filters):
                handles[int(handle.phead.h)] = handle
            session_handles[sid] = handles

        # Each WindowStation 
        for wndsta in windowstations.WndScan(self._config).calculate():
            session = sesses.get(int(wndsta.dwSessionId), None)
            # The session is unknown 
            if not session:
                continue
            handles = session_handles.get(int(session.SessionId), None)
            # No handles in the session 
            if not handles:
                continue
            clip_array = wndsta.pClipBase.dereference()
            # The tagCLIP array is empty or the pointer is invalid 
            if not clip_array:
                continue
            # Resolve tagCLIPDATA from tagCLIP.hData 
            for clip in clip_array:
                handle = handles.get(int(clip.hData), e0)
                # Remove this handle from the list 
                if handle:
                    handles.pop(int(clip.hData))
                yield session, wndsta, clip, handle

        # Any remaining tagCLIPDATA not matched. This allows us
        # to still find clipboard data if a window station is not
        # found or if pClipData or cNumClipFormats were corrupt
        for sid in sesses.keys():
            handles = session_handles.get(sid, None)
            # No handles in the session 
            if not handles:
                continue
            for handle in handles.values():
                yield sesses[sid], e1, e2, handle

    def render_text(self, outfd, data):

        self.table_header(outfd,
                         [("Session", "10"),
                          ("WindowStation", "12"),
                          ("Format", "18"),
                          ("Handle", "[addr]"),
                          ("Object", "[addrpad]"),
                          ("Data", "50"),
                         ])

        for session, wndsta, clip, handle in data:

            # If no tagCLIP is provided, we do not know the format
            if not clip:
                fmt = obj.NoneObject("Format unknown")
            else:
                # Try to get the format name, but failing that, print 
                # the format number in hex instead. 
                if clip.fmt.v() in consts.CLIPBOARD_FORMAT_ENUM:
                    fmt = str(clip.fmt)
                else:
                    fmt = hex(clip.fmt.v())

            # Try to get the handle from tagCLIP first, but
            # fall back to using _HANDLEENTRY.phead. Note: this can
            # be a value like DUMMY_TEXT_HANDLE (1) etc.
            if clip:
                handle_value = clip.hData
            else:
                handle_value = handle.phead.h

            clip_data = ""
            if handle and "TEXT" in fmt:
                clip_data = handle.reference_object().as_string(fmt)

            self.table_row(outfd,
                           session.SessionId,
                           wndsta.Name,
                           fmt,
                           handle_value,
                           handle.phead.v(),
                           clip_data)

            # Print an additional hexdump if --verbose is specified
            if self._config.VERBOSE and handle:
                hex_dump = handle.reference_object().as_hex()
                outfd.write("{0}".format(hex_dump))
