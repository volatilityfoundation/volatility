# Volatility
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

import os.path
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.proc_maps as linux_proc_maps

class linux_dump_map(linux_common.AbstractLinuxCommand):
    """ Writes selected memory mappings to disk """

    def __init__(self, config, *args):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('VMA', short_option = 's', default = None, help = 'Filter by VMA starting address', action = 'store', type = 'long')
        self._config.add_option('OUTPUTFILE', short_option = 'O', default = None, help = 'Output File', action = 'store', type = 'str')

    def read_addr_range(self, task, start, end):
        pagesize = 4096 

        # set the as with our new dtb so we can read from userland
        proc_as = task.get_process_address_space()

        # xrange doesn't support longs :(
        while start < end:
            page = proc_as.zread(start, pagesize)
            yield page
            start = start + pagesize

    def calculate(self):
        linux_common.set_plugin_members(self)
        vmas = linux_proc_maps.linux_proc_maps(self._config).calculate()

        for (task, vma) in vmas:
            if not self._config.VMA or vma.vm_start == self._config.VMA:
                for page in self.read_addr_range(task, vma.vm_start, vma.vm_end):
                    if page:
                        yield page

    def render_text(self, outfd, data):
        if not self._config.OUTPUTFILE:
            debug.error("Please specify an OUTPUTFILE")
        elif os.path.exists(self._config.OUTPUTFILE):
            debug.error("Cowardly refusing to overwrite an existing file")

        outfd.write("Writing to file: {0}\n".format(self._config.OUTPUTFILE))
        outfile = open(self._config.OUTPUTFILE, "wb+")
        size = 0
        for page in data:
            size += len(page)
            outfile.write(page)
        outfile.close()
        outfd.write("Wrote {0} bytes\n".format(size))
