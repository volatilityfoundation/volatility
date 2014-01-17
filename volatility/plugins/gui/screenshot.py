# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
# Copyright (C) 2009 Brendan Dolan-Gavitt 
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

import os
import volatility.plugins.gui.windowstations as windowstations
import volatility.debug as debug

try:
    from PIL import Image, ImageDraw
    has_pil = True
except ImportError:
    has_pil = False

class Screenshot(windowstations.WndScan):
    """Save a pseudo-screenshot based on GDI windows"""

    def __init__(self, config, *args, **kwargs):
        windowstations.WndScan.__init__(self, config, *args, **kwargs)

        config.add_option("DUMP-DIR", short_option = 'D', type = "string",
                          help = "Output directory", action = "store")

    def draw_text(self, draw, text, left, top, fill = "Black"):
        """Label windows in the screen shot"""
        lines = text.split('\x0d\x0a') 
        for line in lines:
            draw.text( (left, top), line, fill = fill)
            _, height = draw.textsize(line)
            top += height

    def render_text(self, outfd, data):

        if not has_pil:
            debug.error("Please install PIL")

        if not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR):
            debug.error("Please supply an existing --dump-dir")

        seen = []

        for window_station in data:
            for desktop in window_station.desktops():

                offset = desktop.PhysicalAddress
                if offset in seen:
                    continue
                seen.append(offset)

                # The foreground window 
                win = desktop.DeskInfo.spwnd
                
                # Some desktops don't have any windows
                if not win:
                    debug.warning("{0}\{1}\{2} has no windows\n".format(
                        desktop.dwSessionId, window_station.Name, desktop.Name))
                    continue

                im = Image.new("RGB", (win.rcWindow.right + 1, win.rcWindow.bottom + 1), "White")
                draw = ImageDraw.Draw(im)

                # Traverse windows, visible only
                for win, _level in desktop.windows(
                                        win = win,
                                        filter = lambda x : 'WS_VISIBLE' in str(x.style)):
                    draw.rectangle(win.rcWindow.get_tup(), outline = "Black", fill = "White")
                    draw.rectangle(win.rcClient.get_tup(), outline = "Black", fill = "White")
                    
                    ## Create labels for the windows 
                    self.draw_text(draw, str(win.strName or ''), win.rcWindow.left + 2, win.rcWindow.top)

                file_name = "session_{0}.{1}.{2}.png".format(
                    desktop.dwSessionId,
                    window_station.Name, desktop.Name)

                file_name = os.path.join(self._config.DUMP_DIR,
                    file_name)

                try:
                    im.save(file_name, "PNG")
                    result = "Wrote {0}".format(file_name)
                except SystemError, why:
                    result = why

                outfd.write("{0}\n".format(result))
