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
import volatility.utils as utils
import volatility.commands as commands
import volatility.cache as cache
import volatility.debug as debug

class CrashInfo(commands.command):
    """Dump crash-dump information"""

    @cache.CacheDecorator("tests/crashinfo")
    def calculate(self):
        """Determines the address space"""
        addr_space = utils.load_as(self._config)

        result = None
        adrs = addr_space
        while adrs:
            if adrs.__class__.__name__ == 'WindowsCrashDumpSpace32':
                result = adrs
            adrs = adrs.base

        if result is None:
            debug.error("Memory Image could not be identified as a crash dump")

        return result

    def render_text(self, outfd, data):
        """Renders the crashdump header as text"""

        hdr = data.get_header()

        outfd.write("DUMP_HEADER32:\n")
        outfd.write(" Majorversion:         0x{0:08x} ({1})\n".format(hdr.MajorVersion, hdr.MajorVersion))
        outfd.write(" Minorversion:         0x{0:08x} ({1})\n".format(hdr.MinorVersion, hdr.MinorVersion))
        outfd.write(" KdSecondaryVersion    0x{0:08x}\n".format(hdr.KdSecondaryVersion))
        outfd.write(" DirectoryTableBase    0x{0:08x}\n".format(hdr.DirectoryTableBase))
        outfd.write(" PfnDataBase           0x{0:08x}\n".format(hdr.PfnDataBase))
        outfd.write(" PsLoadedModuleList    0x{0:08x}\n".format(hdr.PsLoadedModuleList))
        outfd.write(" PsActiveProcessHead   0x{0:08x}\n".format(hdr.PsActiveProcessHead))
        outfd.write(" MachineImageType      0x{0:08x}\n".format(hdr.MachineImageType))
        outfd.write(" NumberProcessors      0x{0:08x}\n".format(hdr.NumberProcessors))
        outfd.write(" BugCheckCode          0x{0:08x}\n".format(hdr.BugCheckCode))
        outfd.write(" PaeEnabled            0x{0:08x}\n".format(hdr.PaeEnabled))
        outfd.write(" KdDebuggerDataBlock   0x{0:08x}\n".format(hdr.KdDebuggerDataBlock))
        outfd.write(" ProductType           0x{0:08x}\n".format(hdr.ProductType))
        outfd.write(" SuiteMask             0x{0:08x}\n".format(hdr.SuiteMask))
        outfd.write(" WriterStatus          0x{0:08x}\n".format(hdr.WriterStatus))

        outfd.write("\nPhysical Memory Description:\n")
        outfd.write("Number of runs: {0}\n".format(len(data.get_runs())))
        outfd.write("FileOffset    Start Address    Length\n")
        foffset = 0x1000
        run = []
        for run in data.get_runs():
            outfd.write("{0:08x}      {1:08x}         {2:08x}\n".format(foffset, run[0] * 0x1000, run[1] * 0x1000))
            foffset += (run[1] * 0x1000)
        outfd.write("{0:08x}      {1:08x}\n".format(foffset - 0x1000, ((run[0] + run[1] - 1) * 0x1000)))
