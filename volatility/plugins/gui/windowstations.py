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
import volatility.scan as scan
import volatility.utils as utils
import volatility.plugins.filescan as filescan
import volatility.plugins.common as common
import volatility.plugins.gui.sessions as sessions

class PoolScanWind(scan.PoolScanner):
    """PoolScanner for window station objects"""

    def object_offset(self, found, address_space):
        """ This returns the offset of the object contained within
        this pool allocation.
        """
        pool_base = found - \
                self.buffer.profile.get_obj_offset('_POOL_HEADER', 'PoolTag')

        pool_obj = obj.Object("_POOL_HEADER", vm = address_space,
                                 offset = pool_base)

        pool_alignment = obj.VolMagic(address_space).PoolAlignment.v()

        object_base = (pool_base + pool_obj.BlockSize * pool_alignment -
                       common.pool_align(address_space,
                      'tagWINDOWSTATION', pool_alignment))

        return object_base

    checks = [ ('PoolTagCheck', dict(tag = "Win\xe4")),
               # seen as 0x98 on xpsp2 and xpsp3, 0x90 on w2k3*, 0xa0 on w7sp0
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x90)),
               # only look in non-paged or free pools
               ('CheckPoolType', dict(paged = False, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class WndScan(filescan.FileScan, sessions.SessionsMixin):
    """Pool scanner for tagWINDOWSTATION (window stations)"""

    def calculate(self):
        flat_space = utils.load_as(self._config, astype = 'physical')
        kernel_space = utils.load_as(self._config)

        # Scan for window station objects 
        for offset in PoolScanWind().scan(flat_space):

            window_station = obj.Object("tagWINDOWSTATION",
                offset = offset, vm = flat_space)

            # Basic sanity checks are included here 
            if not window_station.is_valid():
                continue

            # Find an address space for this window station's session  
            session = self.find_session_space(
                kernel_space, window_station.dwSessionId)

            if not session:
                continue

            # Reset the object's native VM so pointers are
            # dereferenced in session space 
            window_station.set_native_vm(session.obj_vm)

            for winsta in window_station.traverse():
                if winsta.is_valid():
                    yield winsta

    def render_text(self, outfd, data):

        seen = []

        for window_station in data:

            offset = window_station.PhysicalAddress
            if offset in seen:
                continue
            seen.append(offset)

            outfd.write("*" * 50 + "\n")
            outfd.write("WindowStation: {0:#x}, Name: {1}, Next: {2:#x}\n".format(
                offset,
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
