# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import os
import volatility.debug as debug
import volatility.utils as utils
import volatility.commands as commands

class ImageCopy(commands.Command):
    """Copies a physical address space out as a raw DD image"""

    def __init__(self, *args, **kwargs):
        commands.Command.__init__(self, *args, **kwargs)
        self._config.add_option("BLOCKSIZE", short_option = "b", default = 1024 * 1024 * 5,
                                help = "Size (in bytes) of blocks to copy",
                                action = 'store', type = 'int')
        self._config.add_option("OUTPUT-IMAGE", short_option = "O", default = None,
                                help = "Writes a raw DD image out to OUTPUT-IMAGE",
                                action = 'store', type = 'str')

    def calculate(self):
        blocksize = self._config.BLOCKSIZE
        addr_space = utils.load_as(self._config, astype = 'physical')

        for s, l in addr_space.get_available_addresses():
            for i in range(s, s + l, blocksize):
                yield i, addr_space.read(i, min(blocksize, s + l - i))

    def human_readable(self, value):
        for i in ['B', 'KB', 'MB', 'GB']:
            if value < 800:
                return "{0:0.2f} {1:s}".format(value, i)
            value = value / 1024.0
        return "{0:0.2f} TB".format(value)

    def render_text(self, outfd, data):
        """Renders the file to disk"""
        if self._config.OUTPUT_IMAGE is None:
            debug.error("Please provide an output-image filename")

        if os.path.exists(self._config.OUTPUT_IMAGE) and (os.path.getsize(self._config.OUTPUT_IMAGE) > 1):
            debug.error("Refusing to overwrite an existing file, please remove it before continuing")

        outfd.write("Writing data (" + self.human_readable(self._config.BLOCKSIZE) + " chunks): |")
        f = file(self._config.OUTPUT_IMAGE, "wb+")
        try:
            for o, block in data:
                f.seek(o)
                f.write(block)
                outfd.write(".")
                outfd.flush()
        except TypeError:
            debug.error("Error when reading from address space")
        outfd.write("|\n")
