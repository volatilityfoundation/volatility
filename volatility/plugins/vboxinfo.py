# Volatility
# Copyright (C) 2009-2012 Volatility Foundation
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
from volatility import renderers
from volatility.commands import Command

import volatility.plugins.crashinfo as crashinfo
from volatility.renderers.basic import Address, Hex

class VBoxInfo(crashinfo.CrashInfo):
    """Dump virtualbox information"""

    target_as = ['VirtualBoxCoreDumpElf64']

    def unified_output(self, data):
        return renderers.TreeGrid([("FileOffset", Address),
                                 ("Memory Offset", Address),
                                 ("Size", Hex)],
                                  self.generator(data))

    def generator(self, data):
        for memory_offset, file_offset, length in data.get_runs():
            yield (0, [Address(file_offset),
                                  Address(memory_offset),
                                  Hex(length)])

    def render_text(self, outfd, data):

        header = data.get_header()

        outfd.write("Magic: {0:#x}\n".format(header.u32Magic))
        outfd.write("Format: {0:#x}\n".format(header.u32FmtVersion))
        outfd.write("VirtualBox {0}.{1}.{2} (revision {3})\n".format(
                header.Major,
                header.Minor, header.Build,
                header.u32VBoxRevision))
        outfd.write("CPUs: {0}\n\n".format(header.cCpus))

        Command.render_text(self, outfd, data)
    
class QemuInfo(VBoxInfo):
    """Dump Qemu information"""

    target_as = ['QemuCoreDumpElf']

    def render_text(self, outfd, data):
        Command.render_text(self, outfd, data)