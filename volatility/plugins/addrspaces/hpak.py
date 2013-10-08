# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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

import zlib
import volatility.obj as obj
import volatility.plugins.addrspaces.standard as standard

class HPAKVTypes(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
            'HPAK_HEADER' : [ 0x20, { 
                'Magic' : [ 0, ['String', dict(length = 4)]], 
                }], 
            'HPAK_SECTION': [ 0xE0, { 
                'Header' : [ 0, ['String', dict(length = 32)]], 
                'Compressed' : [ 0x8C, ['unsigned int']], 
                'Length' : [ 0x98, ['unsigned long long']], 
                'Offset' : [ 0xA8, ['unsigned long long']], 
                'NextSection' : [ 0xB0, ['unsigned long long']], 
                'Name' : [ 0xD4, ['String', dict(length = 12)]], 
                }], 
            })
        profile.object_classes.update({'HPAK_HEADER': HPAK_HEADER})
            
class HPAK_HEADER(obj.CType):
    """A class for B.S. Hairy headers"""
    
    def Sections(self):
    
        ## The initial section object 
        section = obj.Object("HPAK_SECTION", 
                             offset = self.obj_vm.profile.get_obj_size("HPAK_HEADER"), 
                             vm = self.obj_vm)
        
        ## Iterate through the sections 
        while section.is_valid():
            yield section 
            section = section.NextSection.dereference_as("HPAK_SECTION") 

class HPAKAddressSpace(standard.FileAddressSpace):
    """ This AS supports the HPAK format """
    
    order = 30
    
    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        standard.FileAddressSpace.__init__(self, base, config, layered = True, **kwargs)
                
        self.header = obj.Object("HPAK_HEADER", offset = 0, vm = base)
                
        ## Check the magic 
        self.as_assert(self.header.Magic == 'HPAK', "Invalid magic found")
                
        self.physmem = None
                
        ## cycle though looking for the PHYSDUMP header
        for section in self.header.Sections():
            if str(section.Header) == "HPAKSECTHPAK_SECTION_PHYSDUMP":
                self.physmem = section
                break
        
        self.as_assert(self.physmem is not None, "Cannot find the PHYSDUMP section")
                        
    def read(self, addr, length):
        return self.base.read(addr + self.physmem.Offset, length)
        
    def zread(self, addr, length):
        return self.base.zread(addr + self.physmem.Offset, length)
        
    def is_valid_address(self, addr):
        return self.base.is_valid_address(addr + self.physmem.Offset)
        
    def get_header(self):
        return self.header
        
    def convert_to_raw(self, outfd):
        """The standard imageinfo plugin won't work on 
        hpak images so we provide this method. It wraps
        the zlib compression if necessary"""
        
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        
        chunk_size = 4096
        chunks = self.physmem.Length / chunk_size
        
        def get_chunk(addr, size):
            buffer = self.base.read(addr, size)
            if self.physmem.Compressed == 1:
                buffer = d.decompress(buffer)
            return buffer
        
        for i in range(chunks):
            outfd.write(get_chunk(self.physmem.Offset + i * chunk_size, chunk_size))
            yield i 
            
        leftover = self.physmem.Length % chunk_size
        
        if leftover > 0:
            outfd.write(get_chunk(self.physmem.Offset + i * chunk_size, leftover))
