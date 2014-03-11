# Volatility
#
# Authors:
# Sebastien Bourdon-Richard
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

"""
@author:       Sebastien Bourdon-Richard
@license:      GNU General Public License 2.0 or later
"""

import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.conf as conf
import sys, urllib, copy, os        
import volatility.plugins.addrspaces.vmware as vmware
import volatility.plugins.addrspaces.standard as standard
import volatility.obj as obj
                
class VMEMAddressSpace(addrspace.AbstractRunBasedMemory):
    """ This AS supports the VMEM format with VMSN/VMSS metadata """
    
    order = 30
    vmem_address_space = True 
    PAGE_SIZE = 4096
    
    def __init__(self, base, config, **kwargs):

        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)

        self.as_assert(not (hasattr(base, 'vmem_address_space') and base.vmem_address_space), 
                "Can not stack over another vmem")

        self.as_assert(config.LOCATION.startswith("file://"), 
                'Location is not of file scheme')

        ## Build a path to the vmss - it should be relative 
        ## to the vmem and have the same base name 
        location = os.path.abspath(config.LOCATION[7:])
        location = urllib.url2pathname(location)
        path = os.path.splitext(location)[0]
        metadata = path + ".vmss"

        self.as_assert(os.path.isfile(metadata), 
                'VMware metadata file is not available')

        self.as_assert(location != metadata, 
                'VMware metadata file already detected')

        ## This is a tuple of (physical memory offset, file offset, length)
        self.runs = []
        
        ## Second AS for VMSN/VMSS manipulation
        vmMetaConfig = copy.deepcopy(config)
        vmMetaConfig.LOCATION = "file://" + metadata

        vmss = standard.FileAddressSpace(None, vmMetaConfig)
        header = obj.Object("_VMWARE_HEADER", offset = 0, vm = vmss)

        self.as_assert(header.Magic in [0xbed2bed0, 0xbad1bad1, 0xbed2bed2, 0xbed3bed3],
                       "Invalid VMware signature: {0:#x}".format(header.Magic))
        
        get_tag = vmware.VMWareSnapshotFile.get_tag

        ## The number of memory regions contained in the file 
        region_count = get_tag(header, grp_name = "memory", tag_name = "regionsCount", 
                               data_type = "unsigned int")

        if region_count.is_valid() and region_count != 0:

            ## Create multiple runs - one for each region in the header
            ## Code from vmware.py
            for i in range(region_count):

                memory_offset = get_tag(header, grp_name = "memory", 
                                tag_name = "regionPPN",
                                indices = [i],
                                data_type = "unsigned int") * self.PAGE_SIZE

                file_offset = get_tag(header, grp_name = "memory",
                                tag_name = "regionPageNum", indices = [i],
                                data_type = "unsigned int") * self.PAGE_SIZE
                                
                length = get_tag(header, grp_name = "memory", 
                                tag_name = "regionSize",
                                indices = [i],
                                data_type = "unsigned int") * self.PAGE_SIZE
                                
                self.runs.append((memory_offset, file_offset, length))

        else:
            self.as_assert(False, 'Region count is not valid or 0')     
            
        ## Make sure we found at least one memory run
        self.as_assert(len(self.runs) > 0, "Cannot find any memory run information")