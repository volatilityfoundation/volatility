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

import volatility.plugins.gui.windowstations as windowstations

class DeskScan(windowstations.WndScan):
    """Poolscaner for tagDESKTOP (desktops)"""

    def render_text(self, outfd, data):

        seen = []

        for window_station in data:
            for desktop in window_station.desktops():

                offset = desktop.PhysicalAddress
                if offset in seen:
                    continue
                seen.append(offset)

                outfd.write("*" * 50 + "\n")
                outfd.write("Desktop: {0:#x}, Name: {1}\\{2}, Next: {3:#x}\n".format(
                    offset,
                    desktop.WindowStation.Name,
                    desktop.Name,
                    desktop.rpdeskNext.v(),
                    ))
                outfd.write("SessionId: {0}, DesktopInfo: {1:#x}, fsHooks: {2}\n".format(
                    desktop.dwSessionId,
                    desktop.pDeskInfo.v(),
                    desktop.DeskInfo.fsHooks,
                    ))
                outfd.write("spwnd: {0:#x}, Windows: {1}\n".format(
                    desktop.DeskInfo.spwnd,
                    len(list(desktop.windows(desktop.DeskInfo.spwnd)))
                    ))
                outfd.write("Heap: {0:#x}, Size: {1:#x}, Base: {2:#x}, Limit: {3:#x}\n".format(
                    desktop.pheapDesktop.v(),
                    desktop.DeskInfo.pvDesktopLimit - desktop.DeskInfo.pvDesktopBase,
                    desktop.DeskInfo.pvDesktopBase,
                    desktop.DeskInfo.pvDesktopLimit,
                    ))
                ## This is disabled until we bring in the heaps plugin 
                #if self._config.VERBOSE:
                #    granularity = desktop.obj_vm.profile.get_obj_size("_HEAP_ENTRY")
                #    for entry in desktop.heaps():
                #        outfd.write("  Alloc: {0:#x}, Size: {1:#x} Previous: {2:#x}\n".format(
                #            entry.obj_offset + granularity, 
                #            entry.Size, entry.PreviousSize,
                #            ))
                for thrd in desktop.threads():
                    outfd.write(" {0} ({1} {2} parent {3})\n".format(
                        thrd.pEThread.Cid.UniqueThread,
                        thrd.ppi.Process.ImageFileName,
                        thrd.ppi.Process.UniqueProcessId,
                        thrd.ppi.Process.InheritedFromUniqueProcessId,
                    ))
