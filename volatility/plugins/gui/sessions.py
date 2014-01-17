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

import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.win32.modules as modules
import volatility.win32.tasks as tasks

class SessionsMixin(object):
    """This is a mixin that plugins can inherit for access to the 
    main sessions APIs."""

    def session_spaces(self, kernel_space):
        """ Generators unique _MM_SESSION_SPACE objects
        referenced by active processes. 
    
        @param space: a kernel AS for process enumeration
    
        @yields _MM_SESSION_SPACE instantiated from the 
        session space native_vm. 
        """
        seen = []
        for proc in tasks.pslist(kernel_space):
            if proc.SessionId != None and proc.SessionId.v() not in seen:
                ps_ad = proc.get_process_address_space()
                if ps_ad != None:
                    seen.append(proc.SessionId.v())
                    yield obj.Object("_MM_SESSION_SPACE",
                        offset = proc.Session.v(), vm = ps_ad)

    def find_session_space(self, kernel_space, session_id):
        """ Get a session address space by its ID. 
    
        @param space: a kernel AS for process enumeration
        @param session_id: the session ID to find.
    
        @returns _MM_SESSION_SPACE instantiated from the 
        session space native_vm. 
        """
        for proc in tasks.pslist(kernel_space):
            if proc.SessionId == session_id:
                ps_ad = proc.get_process_address_space()
                if ps_ad != None:
                    return obj.Object("_MM_SESSION_SPACE",
                        offset = proc.Session.v(), vm = ps_ad)
        return obj.NoneObject("Cannot locate a session")

class Sessions(common.AbstractWindowsCommand, SessionsMixin):
    """List details on _MM_SESSION_SPACE (user logon sessions)"""

    def calculate(self):
        kernel_space = utils.load_as(self._config)

        # Once for each unique _MM_SESSION_SPACE 
        for session in self.session_spaces(kernel_space):
            yield session

    def render_text(self, outfd, data):

        # Kernel AS for looking up modules 
        kernel_space = utils.load_as(self._config)

        # Modules sorted for address lookups 
        mods = dict((kernel_space.address_mask(mod.DllBase), mod) for mod in modules.lsmod(kernel_space))
        mod_addrs = sorted(mods.keys())

        for session in data:
            outfd.write("*" * 50 + "\n")
            outfd.write("Session(V): {0:x} ID: {1} Processes: {2}\n".format(
                session.obj_offset,
                session.SessionId,
                len(list(session.processes())),
                ))
            outfd.write("PagedPoolStart: {0:x} PagedPoolEnd {1:x}\n".format(
                session.PagedPoolStart,
                session.PagedPoolEnd,
                ))
            for process in session.processes():
                outfd.write(" Process: {0} {1} {2}\n".format(
                    process.UniqueProcessId,
                    process.ImageFileName,
                    process.CreateTime,
                    ))
            for image in session.images():
                module = tasks.find_module(mods, mod_addrs, kernel_space.address_mask(image.Address))
                outfd.write(" Image: {0:#x}, Address {1:x}, Name: {2}\n".format(
                    image.obj_offset,
                    image.Address,
                    str(module and module.BaseDllName or '')
                    ))
