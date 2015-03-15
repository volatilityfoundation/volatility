# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import re
import sre_constants
import struct
import volatility.plugins.procdump as procdump
import volatility.win32 as win32
import volatility.obj as obj
import volatility.utils as utils
import volatility.debug as debug
import volatility.exceptions as exceptions
from volatility.renderers import TreeGrid

class VerInfo(procdump.ProcDump):
    """Prints out the version information from PE images"""

    def __init__(self, config, *args, **kwargs):
        procdump.ProcDump.__init__(self, config, *args, **kwargs)
        config.remove_option("OFFSET")
        config.remove_option("PID")
        config.add_option("OFFSET", short_option = "o", type = 'int',
                          help = "Offset of the module to print the version information for")
        config.add_option('REGEX', short_option = "r", default = None,
                          help = 'Dump modules matching REGEX')
        config.add_option('IGNORE-CASE', short_option = 'i', action = 'store_true',
                      help = 'ignore case in pattern match', default = False)

    def calculate(self):
        """Returns a unique list of modules"""
        addr_space = utils.load_as(self._config)

        if self._config.REGEX is not None:
            try:
                if self._config.IGNORE_CASE:
                    module_pattern = re.compile(self._config.REGEX, flags = sre_constants.SRE_FLAG_IGNORECASE)
                else:
                    module_pattern = re.compile(self._config.REGEX)
            except sre_constants.error, e:
                debug.error('Regular expression parsing error: {0}'.format(e))

        if self._config.OFFSET is not None:
            if not addr_space.is_valid_address(self._config.OFFSET):
                debug.error("Specified offset is not valid for the provided address space")
            pefile = obj.Object("_IMAGE_DOS_HEADER", self._config.OFFSET, addr_space)
            if pefile.is_valid():
                yield None, pefile
            raise StopIteration

        tasks = win32.tasks.pslist(addr_space)

        for task in tasks:
            process_space = task.get_process_address_space()
            for module in task.get_load_modules():
                if self._config.REGEX is not None:
                    if not (module_pattern.search(str(module.FullDllName))
                            or module_pattern.search(str(module.BaseDllName))):
                        continue
                pefile = obj.Object("_IMAGE_DOS_HEADER", module.DllBase, process_space)
                if pefile.is_valid():
                    yield module, pefile

    def unified_output(self, data):
        return TreeGrid([("Module", str),
                       ("FileVersion", str),
                       ("ProductVersion", str),
                       ("Flags", str),
                       ("OS", str),
                       ("FileType", str),
                       ("FileDate", str), 
                       ("InfoString", str)],
                        self.generator(data))

    def generator(self, data):
        for module, pefile in data:
            if module:
                name = str(module.FullDllName)
            vinfo = pefile.get_version_info()
            if vinfo != None:
                fileversion = "{0}".format(vinfo.FileInfo.file_version())
                prodversion = "{0}".format(vinfo.FileInfo.product_version())
                flags = "{0}".format(vinfo.FileInfo.flags())
                os = "{0}".format(vinfo.FileInfo.FileOS)
                filetype = "{0}".format(vinfo.FileInfo.file_type())
                filedate = "{0}".format(vinfo.FileInfo.FileDate or '')
                infostring = ""
                for string, value in vinfo.get_file_strings():
                    infostring += "{0} : {1}".format(string, value)
                yield (0, [name,
                            fileversion,
                            prodversion,
                            flags,
                            os,
                            filetype,
                            filedate,
                            infostring])
            else:
                yield (0, [name, "", "", "", "", "", "", ""])

    def render_text(self, outfd, data):
        """Renders the text"""
        for module, pefile in data:
            if module:
                outfd.write(str(module.FullDllName))
            outfd.write("\n")
            vinfo = pefile.get_version_info()
            if vinfo != None:
                outfd.write("  File version    : {0}\n".format(vinfo.FileInfo.file_version()))
                outfd.write("  Product version : {0}\n".format(vinfo.FileInfo.product_version()))
                outfd.write("  Flags           : {0}\n".format(vinfo.FileInfo.flags()))
                outfd.write("  OS              : {0}\n".format(vinfo.FileInfo.FileOS))
                outfd.write("  File Type       : {0}\n".format(vinfo.FileInfo.file_type()))
                outfd.write("  File Date       : {0}\n".format(vinfo.FileInfo.FileDate or ''))
                for string, value in vinfo.get_file_strings():
                    outfd.write("  {0} : {1}\n".format(string, value))
