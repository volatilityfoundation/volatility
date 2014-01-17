# Volatility
# Copyright (C) 2009-2013 Volatility Foundation
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

class MachOInfo(crashinfo.CrashInfo):
    """Dump Mach-O file format information"""
    
    target_as = ['MachOAddressSpace']
        
    def render_text(self, outfd, data):
    
        header = data.get_header()
        
        outfd.write("Magic: {0:#x}\n".format(header.magic))
        outfd.write("Architecture: {0}-bit\n".format(data.bits))
        
        self.table_header(outfd, [("File Offset", "[addrpad]"), 
                                  ("Memory Offset", "[addrpad]"), 
                                  ("Size", "[addrpad]"), 
                                  ("Name", "")])
        
        for seg in data.segs:
            self.table_row(outfd, seg.fileoff, seg.vmaddr, seg.vmsize, seg.segname)
