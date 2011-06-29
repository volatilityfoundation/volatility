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
import volatility.obj as obj
import volatility.commands as commands
import volatility.debug as debug
import volatility.cache as cache

class HibInfo(commands.command):
    """Dump hibernation file information"""

    @cache.CacheDecorator("tests/hibinfo")
    def calculate(self):
        """Determines the address space"""
        addr_space = utils.load_as(self._config)

        result = None
        adrs = addr_space
        while adrs:
            if adrs.__class__.__name__ == 'WindowsHiberFileSpace32':
                sr = adrs.ProcState.SpecialRegisters

                entrysize = adrs.profile.get_obj_size("_KGDTENTRY")
                entry = obj.Object("_KGDTENTRY", sr.Gdtr.Base + ((0x3B >> 3) * entrysize), addr_space)
                NtTibAddress = (entry.BaseLow) | (entry.BaseMid << (2 * 8)) | (entry.BaseHigh << (3 * 8))

                teb = obj.NoneObject("NtTibAddress out of range")
                if not ((NtTibAddress == 0) or (NtTibAddress > 0x80000000)):
                    teb = obj.Object("_TEB", NtTibAddress, addr_space)

                result = {'header': adrs.get_header(),
                          'sr': sr,
                          'peb': teb.ProcessEnvironmentBlock,
                          'adrs': adrs }
            adrs = adrs.base

        if result == None:
            debug.error("Memory Image could not be identified or did not contain hiberation information")

        return result

    def render_text(self, outfd, data):
        """Renders the hiberfil header as text"""

        hdr = data['header']
        sr = data['sr']
        peb = data['peb']

        outfd.write("IMAGE_HIBER_HEADER:\n")
        outfd.write(" Signature: {0}\n".format(hdr.Signature))
        outfd.write(" SystemTime: {0}\n".format(hdr.SystemTime))

        outfd.write("\nControl registers flags\n")
        outfd.write(" CR0: {0:08x}\n".format(sr.Cr0))
        outfd.write(" CR0[PAGING]: {0}\n".format((sr.Cr0 >> 31) & 1))
        outfd.write(" CR3: {0:08x}\n".format(sr.Cr3))
        outfd.write(" CR4: {0:08x}\n".format(sr.Cr4))
        outfd.write(" CR4[PSE]: {0}\n".format((sr.Cr4 >> 4) & 1))
        outfd.write(" CR4[PAE]: {0}\n".format((sr.Cr4 >> 5) & 1))

        outfd.write("\nWindows Version is {0}.{1} ({2})\n\n".format(peb.OSMajorVersion, peb.OSMinorVersion, peb.OSBuildNumber))

class HibDump(HibInfo):
    """Dumps the hibernation file to a raw file"""

    def __init__(self, config, *args):
        HibInfo.__init__(self, config, *args)
        config.add_option("DUMP-FILE", short_option = "D", default = None,
                          cache_invalidator = False,
                          help = "Specifies the output dump file")

    def render_text(self, outfd, data):
        """Renders the text output of hibneration file dumping"""
        if not self._config.DUMP_FILE:
            debug.error("Hibdump requires an output file to dump the hibernation file")

        if os.path.exists(self._config.DUMP_FILE):
            debug.error("File " + self._config.DUMP_FILE + " already exists, please choose another file or delete it first")

        outfd.write("Converting hibernation file...\n")

        f = open(self._config.DUMP_FILE, 'wb')
        total = data['adrs'].get_number_of_pages()
        for pagenum in data['adrs'].convert_to_raw(f):
            outfd.write("\r" + ("{0:08x}".format(pagenum)) + " / " + ("{0:08x}".format(total)) + " converted (" + ("{0:03d}".format(pagenum * 100 / total)) + "%)")
        f.close()
        outfd.write("\n")
