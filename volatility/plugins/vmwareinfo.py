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

import os
import volatility.plugins.crashinfo as crashinfo
import volatility.utils as utils

class VMwareInfo(crashinfo.CrashInfo):
    """Dump VMware VMSS/VMSN information"""
    
    target_as = ['VMWareSnapshotFile']

    def __init__(self, config, *args, **kwargs):
        crashinfo.CrashInfo.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          help = 'Directory in which to dump the screenshot (if available)')
        
    def render_text(self, outfd, data):
    
        header = data.get_header()
        
        ## First some of the version meta-data
        outfd.write("Magic: {0:#x} (Version {1})\n".format(header.Magic, header.Version))
        outfd.write("Group count: {0:#x}\n".format(header.GroupCount))
        
        ## Now let's print the runs 
        self.table_header(outfd, [("File Offset", "#018x"), 
                                  ("PhysMem Offset", "#018x"),
                                  ("Size", "#018x")])
        
        for memory_offset, file_offset, length in data.get_runs():
            self.table_row(outfd, file_offset, memory_offset, length)
            
        outfd.write("\n")
        
        ## Go through and print the groups and tags
        self.table_header(outfd, [("DataOffset", "#018x"), 
                                  ("DataSize", "#018x"), 
                                  ("Name", "50"), 
                                  ("Value", "")])
    
        for group in header.Groups:
            for tag in group.Tags:
            
                ## The indices should look like [0][1] 
                indices = ""
                for i in tag.TagIndices:
                    indices += "[{0}]".format(i)
                    
                ## Attempt to format standard values
                if tag.DataMemSize == 0:
                    value = ""
                elif tag.DataMemSize == 1:
                    value = "{0}".format(tag.cast_as("unsigned char"))
                elif tag.DataMemSize == 2:
                    value = "{0}".format(tag.cast_as("unsigned short"))
                elif tag.DataMemSize == 4:
                    value = "{0:#x}".format(tag.cast_as("unsigned int"))
                elif tag.DataMemSize == 8:
                    value = "{0:#x}".format(tag.cast_as("unsigned long long"))
                else:
                    value = ""
                                        
                self.table_row(outfd, 
                               tag.RealDataOffset,
                               tag.DataMemSize, 
                               "{0}/{1}{2}".format(group.Name, tag.Name, indices), 
                               value)
                               
                ## In verbose mode, when we're *not* dealing with memory segments, 
                ## print a hexdump of the data 
                if (self._config.VERBOSE and tag.DataMemSize > 0 
                        and str(group.Name) != "memory" and value == ""):
                        
                    ## When we read, it must be done via the AS base (FileAddressSpace)
                    addr = tag.RealDataOffset
                    data = tag.obj_vm.read(addr, tag.DataMemSize)
                    
                    outfd.write("".join(["{0:#010x}  {1:<48}  {2}\n".format(addr + o, h, ''.join(c))
                                for o, h, c in utils.Hexdump(data)
                                ]))
                     
                    ## If an output directory was supplied, extract the 
                    ## snapshot thumbnail image using the code below. 
                    if (self._config.DUMP_DIR and 
                                str(group.Name) == "MKSVMX" and 
                                str(tag.Name) == "imageData"):
                        full_path = os.path.join(self._config.DUMP_DIR, "screenshot.png")
                        with open(full_path, "wb") as fh:
                            fh.write(data)
                            outfd.write("Wrote screenshot to: {0}\n".format(full_path))
                    
                    
