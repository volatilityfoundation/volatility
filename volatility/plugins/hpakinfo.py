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

import volatility.plugins.crashinfo as crashinfo
import volatility.debug as debug

class HPAKInfo(crashinfo.CrashInfo):
    """Info on an HPAK file"""
    
    target_as = ['HPAKAddressSpace'] 
    
    def render_text(self, outfd, data):
        
        header = data.get_header()
        
        for section in header.Sections():
            outfd.write("Header:     {0}\n".format(section.Header))
            outfd.write("Length:     {0:#x}\n".format(section.Length))
            outfd.write("Offset:     {0:#x}\n".format(section.Offset))
            outfd.write("NextOffset: {0:#x}\n".format(section.NextSection))
            outfd.write("Name:       {0}\n".format(section.Name))
            outfd.write("Compressed: {0}\n".format(section.Compressed))
            outfd.write("\n")
            
class HPAKExtract(HPAKInfo):
    """Extract physical memory from an HPAK file"""
    
    def render_text(self, outfd, data):
            
        if not self._config.OUTPUT_FILE:
            debug.error("You must supply --output-file")
            
        header = data.get_header()

        data.convert_to_raw(outfd)
        
        print "Done."
