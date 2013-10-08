# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.debug as debug
import volatility.cache as cache
import volatility.win32.tasks as tasks

class HibInfo(common.AbstractWindowsCommand):
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

                peb = obj.NoneObject("Cannot locate a valid PEB")

                # Find the PEB by cycling through processes. This method works 
                # on all versions of Windows x86 and x64. 
                for task in tasks.pslist(addr_space):
                    if task.Peb:
                        peb = task.Peb
                        break

                result = {'header': adrs.get_header(),
                          'sr': sr,
                          'peb': peb,
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

        outfd.write("PO_MEMORY_IMAGE:\n")
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
