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
import volatility.debug as debug
import volatility.poolscan as poolscan
import volatility.plugins.common as common
import volatility.plugins.gui.sessions as sessions

class PoolScanWind(poolscan.PoolScanner):
    """PoolScanner for window station objects"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.struct_name = "tagWINDOWSTATION"
        self.object_type = "WindowStation"
        self.pooltag = obj.VolMagic(address_space).WindPoolTag.v()
        size = 0x90 # self.address_space.profile.get_obj_size("tagWINDOWSTATION")

        self.checks = [
               # seen as 0x98 on xpsp2 and xpsp3, 0x90 on w2k3*, 0xa0 on w7sp0
               ('CheckPoolSize', dict(condition = lambda x: x >= size)),
               # only look in non-paged or free pools
               ('CheckPoolType', dict(paged = False, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class WndScan(common.AbstractScanCommand, sessions.SessionsMixin):
    """Pool scanner for window stations"""

    scanners = [PoolScanWind]
    
    def calculate(self):
        addr_space = utils.load_as(self._config)

        seen = []

        for wind in self.scan_results(addr_space):
            
            # Find an address space for this window station's session  
            session = self.find_session_space(
                addr_space, wind.dwSessionId)

            if not session:
                continue

            # Reset the object's native VM so pointers are
            # dereferenced in session space 
            wind.set_native_vm(session.obj_vm)

            for winsta in wind.traverse():
                if winsta.is_valid():

                    offset = winsta.PhysicalAddress
                    if offset in seen:
                        continue
                    seen.append(offset)

                    yield winsta

    def render_text(self, outfd, data):

        for window_station in data:

            outfd.write("*" * 50 + "\n")
            outfd.write("WindowStation: {0:#x}, Name: {1}, Next: {2:#x}\n".format(
                window_station.PhysicalAddress,
                window_station.Name,
                window_station.rpwinstaNext.v(),
                ))
            outfd.write("SessionId: {0}, AtomTable: {1:#x}, Interactive: {2}\n".format(
                window_station.dwSessionId,
                window_station.pGlobalAtomTable,
                window_station.Interactive,
                ))
            outfd.write("Desktops: {0}\n".format(
                ', '.join([desk.Name for desk in window_station.desktops()])
                ))
            outfd.write("ptiDrawingClipboard: pid {0} tid {1}\n".format(
                window_station.ptiDrawingClipboard.pEThread.Cid.UniqueProcess,
                window_station.ptiDrawingClipboard.pEThread.Cid.UniqueThread
                ))
            outfd.write("spwndClipOpen: {0:#x}, spwndClipViewer: {1:#x} {2} {3}\n".format(
                window_station.spwndClipOpen.v(),
                window_station.spwndClipViewer.v(),
                str(window_station.LastRegisteredViewer.UniqueProcessId or ""),
                str(window_station.LastRegisteredViewer.ImageFileName or ""),
                ))
            outfd.write("cNumClipFormats: {0}, iClipSerialNumber: {1}\n".format(
                window_station.cNumClipFormats,
                window_station.iClipSerialNumber,
                ))
            outfd.write("pClipBase: {0:#x}, Formats: {1}\n".format(
                window_station.pClipBase,
                ",".join([str(clip.fmt) for clip in window_station.pClipBase.dereference()]),
                ))
