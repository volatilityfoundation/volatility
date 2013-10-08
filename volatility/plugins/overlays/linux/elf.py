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

# ELF64 format: http://downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf

import volatility.obj as obj

class elf64_hdr(obj.CType):
    """An ELF64 header"""
    
    def program_headers(self):
        return obj.Object("Array", targetType = "elf64_phdr", 
                          offset = self.obj_offset + self.e_phoff, 
                          count = self.e_phnum, vm = self.obj_vm)
    
class elf64_note(obj.CType):
    """An ELF64 note header"""
    
    def cast_descsz(self, obj_type):
        """Cast the descsz member as a specified type. 
        
        @param obj_type: name of the object 
        
        The descsz member is at a variable offset, which depends
        on the length of the namesz string which precedes it. The
        string is 8-byte aligned and can be zero. 
        """
        
        desc_offset = (self.obj_offset + 
                       self.obj_vm.profile.get_obj_size("elf64_note") + 
                       ((((self.n_namesz - 1) >> 3) + 1) << 3))
                       
        return obj.Object(obj_type, offset = desc_offset, vm = self.obj_vm)    
    
class ELF64Modification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
            'elf64_hdr' : [ 64, {
                'e_ident' : [ 0, ['String', dict(length = 16)]], 
                'e_type' : [ 16, ['Enumeration', dict(target = 'unsigned short', choices = {
                    0: 'ET_NONE', 
                    1: 'ET_REL', 
                    2: 'ET_EXEC', 
                    3: 'ET_DYN', 
                    4: 'ET_CORE', 
                    0xff00: 'ET_LOPROC', 
                    0xffff: 'ET_HIPROC'})]],
                'e_machine' : [ 18, ['unsigned short']], 
                'e_version' : [ 20, ['unsigned int']], 
                'e_entry' : [ 24, ['unsigned long long']], 
                'e_phoff' : [ 32, ['unsigned long long']], 
                'e_shoff' : [ 40, ['unsigned long long']], 
                'e_flags' : [ 48, ['unsigned int']], 
                'e_ehsize' : [ 52, ['unsigned short']], 
                'e_phentsize' : [ 54, ['unsigned short']], 
                'e_phnum' : [ 56, ['unsigned short']], 
                'e_shentsize' : [ 58, ['unsigned short']], 
                'e_shnum' : [ 60, ['unsigned short']], 
                'e_shstrndx' : [ 62, ['unsigned short']], 
                }], 
            'elf64_phdr' : [ 56, {
                'p_type' : [ 0, ['Enumeration', dict(target = 'unsigned int', choices = {
                    0: 'PT_NULL', 
                    1: 'PT_LOAD',
                    2: 'PT_DYNAMIC', 
                    3: 'PT_INTERP', 
                    4: 'PT_NOTE', 
                    5: 'PT_SHLIB', 
                    6: 'PT_PHDR', 
                    7: 'PT_TLS', 
                    0x60000000: 'PT_LOOS', 
                    0x6fffffff: 'PT_HIOS', 
                    0x70000000: 'PT_LOPROC', 
                    0x7fffffff: 'PT_HIPROC'})]],
                'p_flags' : [ 4, ['unsigned int']], 
                'p_offset' : [ 8, ['unsigned long long']], 
                'p_vaddr' : [ 16, ['unsigned long long']], 
                'p_paddr' : [ 24, ['unsigned long long']], 
                'p_filesz' : [ 32, ['unsigned long long']], 
                'p_memsz' : [ 40, ['unsigned long long']], 
                'p_align' : [ 48, ['unsigned long long']], 
                }], 
            'elf64_note' : [ 12, {
                'n_namesz' : [ 0, ['unsigned int']], 
                'n_descsz' : [ 4, ['unsigned int']], 
                'n_type' : [ 8, ['unsigned int']], 
                 ## FIXME: this must be cast to int() because the base AS (FileAddressSpace) read method doesn't understand NativeType.
                 ## Remove the cast after http://code.google.com/p/volatility/issues/detail?id=350 is fixed. 
                'namesz' : [ 12, ['String', dict(length = lambda x : int(x.n_namesz))]], 
                }], 
        })
        profile.object_classes.update({'elf64_hdr': elf64_hdr, 'elf64_note': elf64_note})
