# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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
import volatility.plugins.mac.pstasks as pstasks 
import volatility.debug as debug

class mac_memdump(pstasks.mac_tasks):
    """ Dump addressable memory pages to a file """

    def __init__(self, config, *args, **kwargs):
        pstasks.mac_tasks.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

    def render_text(self, outfd, data):

        if (not self._config.DUMP_DIR or not 
                    os.path.isdir(self._config.DUMP_DIR)):
            debug.error("You must speficy a valid path with -D")

        for proc in data:
            name = "{0:X}.{1}.dmp".format(proc.obj_offset, proc.p_comm)
            path = os.path.join(self._config.DUMP_DIR, name)

            space = proc.get_process_address_space()
            if not space:
                outfd.write("Failed to acquire AS for: {0}\n".format(p_comm))
                continue

            handle = open(path, "wb")
            if not handle:
                outfd.write("Failed to open file for writing: {0}\n".format(path))
                continue

            bytes = 0

            try:
                for page, size in space.get_available_pages():
                    data = space.read(page, size)
                    if not data:
                        continue
                    handle.write(data)
                    bytes += size
                outfd.write("Wrote {0} bytes to {1}\n".format(bytes, path))
            except IOError:
                outfd.write("Error dumping process: {0}\n".format(p_comm))
            finally:
                handle.close()
            
