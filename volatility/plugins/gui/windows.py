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

import volatility.plugins.gui.messagehooks as messagehooks

class WinTree(messagehooks.MessageHooks):
    """Print Z-Order Desktop Windows Tree"""

    def render_text(self, outfd, data):

        for winsta, atom_tables in data:
            for desktop in winsta.desktops():
                outfd.write("*" * 50 + "\n")
                outfd.write("Window context: {0}\\{1}\\{2}\n\n".format(
                    winsta.dwSessionId, winsta.Name, desktop.Name))
                for wnd, level in desktop.windows(desktop.DeskInfo.spwnd):
                    outfd.write("{0}{1} {2} {3}:{4} {5}\n".format(
                            "." * level,
                            str(wnd.strName or '') or "#{0:x}".format(wnd.head.h),
                            "(visible)" if wnd.Visible else "",
                            wnd.Process.ImageFileName,
                            wnd.Process.UniqueProcessId,
                            self.translate_atom(winsta, atom_tables, wnd.ClassAtom),
                            ))

class Windows(messagehooks.MessageHooks):
    """Print Desktop Windows (verbose details)"""

    def render_text(self, outfd, data):

        for winsta, atom_tables in data:
            for desktop in winsta.desktops():
                outfd.write("*" * 50 + "\n")
                outfd.write("Window context: {0}\\{1}\\{2}\n\n".format(
                    winsta.dwSessionId, winsta.Name, desktop.Name))
                for wnd, _level in desktop.windows(desktop.DeskInfo.spwnd):
                    outfd.write("Window Handle: #{0:x} at {1:#x}, Name: {2}\n".format(
                        wnd.head.h, wnd.obj_offset, str(wnd.strName or '')
                    ))
                    outfd.write("ClassAtom: {0:#x}, Class: {1}\n".format(
                        wnd.ClassAtom,
                        self.translate_atom(winsta, atom_tables, wnd.ClassAtom),
                    ))
                    outfd.write("SuperClassAtom: {0:#x}, SuperClass: {1}\n".format(
                        wnd.SuperClassAtom,
                        self.translate_atom(winsta, atom_tables, wnd.SuperClassAtom),
                    ))
                    outfd.write("pti: {0:#x}, Tid: {1} at {2:#x}\n".format(
                        wnd.head.pti.v(),
                        wnd.Thread.Cid.UniqueThread,
                        wnd.Thread.obj_offset,
                    ))
                    outfd.write("ppi: {0:#x}, Process: {1}, Pid: {2}\n".format(
                        wnd.head.pti.ppi.v(),
                        wnd.Process.ImageFileName,
                        wnd.Process.UniqueProcessId,
                    ))
                    outfd.write("Visible: {0}\n".format("Yes" if wnd.Visible else "No"))
                    outfd.write("Left: {0}, Top: {1}, Bottom: {2}, Right: {3}\n".format(
                        wnd.rcClient.left,
                        wnd.rcClient.top,
                        wnd.rcClient.right, wnd.rcClient.bottom
                    ))
                    outfd.write("Style Flags: {0}\n".format(wnd.style))
                    outfd.write("ExStyle Flags: {0}\n".format(wnd.ExStyle))
                    outfd.write("Window procedure: {0:#x}\n".format(
                        wnd.lpfnWndProc,
                    ))
                    outfd.write("\n")
