# Volatility
# Copyright (C) 2009-2012 Volatility Foundation
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

import volatility.plugins.crashinfo as crashinfo

class VBoxInfo(crashinfo.CrashInfo):
    """Dump virtualbox information"""
    
    target_as = ['VirtualBoxCoreDumpElf64']
        
    def render_text(self, outfd, data):
    
        header = data.get_header()
        
        outfd.write("Magic: {0:#x}\n".format(header.u32Magic))
        outfd.write("Format: {0:#x}\n".format(header.u32FmtVersion))
        outfd.write("VirtualBox {0}.{1}.{2} (revision {3})\n".format(
                header.Major, 
                header.Minor, header.Build, 
                header.u32VBoxRevision))
        outfd.write("CPUs: {0}\n\n".format(header.cCpus))
        
        self.table_header(outfd, [("File Offset", "[addrpad]"), 
                                  ("Memory Offset", "[addrpad]"), 
                                  ("Size", "[addrpad]")])
        
        for memory_offset, file_offset, length in data.get_runs():
            self.table_row(outfd, file_offset, memory_offset, length)
