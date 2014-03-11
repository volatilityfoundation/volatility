# Volatility
# Copyright (C) 2007-2011 Volatile Systems
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

# ELF64 format: http://downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf

import volatility.obj as obj

elf32_vtypes = {
    'elf32_hdr' : [ 52, {
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
        'e_entry' : [ 24, ['unsigned int']], 
        'e_phoff' : [ 28, ['unsigned int']], 
        'e_shoff' : [ 32, ['unsigned int']], 
        'e_flags' : [ 36, ['unsigned int']], 
        'e_ehsize'    : [ 40, ['unsigned short']], 
        'e_phentsize' : [ 42, ['unsigned short']], 
        'e_phnum'     : [ 44, ['unsigned short']], 
        'e_shentsize' : [ 46, ['unsigned short']], 
        'e_shnum'     : [ 48, ['unsigned short']], 
        'e_shstrndx'  : [ 50, ['unsigned short']], 
        }], 
 
   'elf32_phdr' : [ 32, {
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
        'p_offset' : [ 4,  ['unsigned int']], 
        'p_vaddr'  : [ 8,  ['unsigned int']], 
        'p_paddr'  : [ 12, ['unsigned int']], 
        'p_filesz' : [ 16, ['unsigned int']], 
        'p_memsz'  : [ 20, ['unsigned int']], 
        'p_flags'  : [ 24, ['unsigned int']], 
        'p_align'  : [ 28, ['unsigned int']], 
        }], 
    
    'elf32_shdr' : [40, { 
        'sh_name'   : [0,  ['unsigned int']],
        'sh_type'   : [4,  ['unsigned int']],
        'sh_flags'  : [8,  ['unsigned int']],
        'sh_addr'   : [12, ['unsigned int']],
        'sh_offset' : [16, ['unsigned int']],
        'sh_size'   : [20, ['unsigned int']],
        'sh_link'   : [24, ['unsigned int']],
        'sh_info'      : [28, ['unsigned int']],
        'sh_addralign' : [32, ['unsigned int']],
        'sh_entisze'   : [36, ['unsigned int']],
        }],

    'elf32_dyn' : [ 8, {
        'd_tag' : [0, ['int']],
        'd_ptr' : [4, ['unsigned int']],
        }],

    'elf32_note' : [ 12, {
        'n_namesz' : [ 0, ['unsigned int']], 
        'n_descsz' : [ 4, ['unsigned int']], 
        'n_type' : [ 8, ['unsigned int']], 
         ## FIXME: this must be cast to int() because the base AS (FileAddressSpace) read method doesn't understand NativeType.
         ## Remove the cast after http://code.google.com/p/volatility/issues/detail?id=350 is fixed. 
        'namesz' : [ 12, ['String', dict(length = lambda x : int(x.n_namesz))]], 
        }],

    'elf32_link_map' : [0, {
        'l_addr' : [0, ['unsigned int']], 
        'l_name' : [4, ['unsigned int']], 
        'l_ld'   : [8, ['unsigned int']], 
        'l_next' : [12, ['unsigned int']], 
        'l_prev' : [16, ['unsigned int']], 
        }],
}

elf64_vtypes = {
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
        'e_ehsize'    : [ 52, ['unsigned short']], 
        'e_phentsize' : [ 54, ['unsigned short']], 
        'e_phnum'     : [ 56, ['unsigned short']], 
        'e_shentsize' : [ 58, ['unsigned short']], 
        'e_shnum'     : [ 60, ['unsigned short']], 
        'e_shstrndx'  : [ 62, ['unsigned short']], 
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

    'elf64_shdr' : [64, { 
        'sh_name'   : [0,  ['unsigned int']],
        'sh_type'   : [4,  ['unsigned int']],
        'sh_flags'  : [8,  ['unsigned long long']],
        'sh_addr'   : [16, ['unsigned long long']],
        'sh_offset' : [24, ['unsigned long long']],
        'sh_size'   : [32, ['unsigned long long']],
        'sh_link'   : [40, ['unsigned int']],
        'sh_info'      : [44, ['unsigned int']],
        'sh_addralign' : [48, ['unsigned long long']],
        'sh_entisze'   : [56, ['unsigned long long']],
        }],

    'elf64_dyn' : [ 16, {
        'd_tag' : [0, ['long long']],
        'd_ptr' : [8, ['unsigned long long']],
        }],

    'elf64_note' : [ 12, {
        'n_namesz' : [ 0, ['unsigned int']], 
        'n_descsz' : [ 4, ['unsigned int']], 
        'n_type' : [ 8, ['unsigned int']], 
         ## FIXME: this must be cast to int() because the base AS (FileAddressSpace) read method doesn't understand NativeType.
         ## Remove the cast after http://code.google.com/p/volatility/issues/detail?id=350 is fixed. 
        'namesz' : [ 12, ['String', dict(length = lambda x : int(x.n_namesz))]], 
        }],

   'elf64_link_map' : [0, {
        'l_addr' : [0, ['unsigned long long']], 
        'l_name' : [8, ['unsigned long long']], 
        'l_ld'   : [16, ['unsigned long long']], 
        'l_next' : [24, ['unsigned long long']], 
        'l_prev' : [32, ['unsigned long long']], 
        }],
}

class elf(obj.CType):
    def __init__(self, is_header, name32, name64, theType, offset, vm, name = None, **kwargs):  
        self.name32 = name32
        self.name64 = name64
        self.elf_obj = None

        if is_header:
            self._init_cache(offset, vm)
        else:
            self.size_cache = -39

        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)
    
    def _init_cache(self, offset, vm):
        self._set_size_cache(offset, vm)
        self._make_elf_obj(offset, vm) 

    def _init_cache_from_parent(self):
        self.size_cache = self.obj_parent.size_cache
        self._make_elf_obj(self.obj_offset, self.obj_vm)

    def _make_elf_obj(self, offset, vm):
        if self.size_cache == 32:
            self.elf_obj = obj.Object(self.name32, offset = offset, vm = vm)
        elif self.size_cache == 64:
            self.elf_obj = obj.Object(self.name64, offset = offset, vm = vm)
        else:
            print "INVALID SIZE CACHE: %d" % self.size_cache
            exit()    

    def _set_size_cache(self, offset, vm):
        ei_class = obj.Object("unsigned char", offset = offset + 4, vm = vm)
        if ei_class == 1:
            self.size_cache = 32
        elif ei_class == 2:
            self.size_cache = 64
        else:
            print "INVALID EI_CLASS: %d" % ei_class
            exit()

    def _get_typename(self, typename):
        if self.size_cache == -39:
            self._init_cache_from_parent()

        if self.size_cache == 32:
            typename = "elf32_" + typename
        else:
            typename = "elf64_" + typename

        return typename

    def __getattr__(self, attr):
        if self.size_cache == -39:
            self._init_cache_from_parent()

        return self.elf_obj.__getattr__(attr)

class elf_hdr(elf):
    """An ELF header"""
    
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 1, "elf32_hdr", "elf64_hdr", theType, offset, vm, name, **kwargs)    

    def program_headers(self):
        rtname = self._get_typename("phdr")
        rtsize = self.obj_vm.profile.get_obj_size(rtname)

        tname = "elf_phdr"
        
        # the buffer of headers
        arr_start = self.obj_offset + self.e_phoff

        for i in range(self.e_phnum):
            # use the real size
            idx = i * rtsize

            phdr = obj.Object("elf_phdr", offset = arr_start + idx, vm = self.obj_vm, parent = self)
            yield phdr  

class elf_phdr(elf):
    """ An elf program header """

    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 0, "elf32_phdr", "elf64_phdr", theType, offset, vm, name = None, **kwargs)    

    def dynamic_sections(self):
        # sanity check
        if str(self.p_type) != 'PT_DYNAMIC':
            print "failed sanity check"
            return

        rtname = self._get_typename("dyn")
        rtsize = self.obj_vm.profile.get_obj_size(rtname)

        tname = "elf_dyn"
        
        # the buffer of array starts at elf_base + our virtual address ( offset )
        arr_start = self.obj_parent.obj_offset + self.p_vaddr

        for i in range(256):
            # use the real size
            idx = i * rtsize

            dyn = obj.Object(tname, offset = arr_start + idx, vm = self.obj_vm, parent = self)
            
            yield dyn  
            
            if dyn.d_tag == 0:
                break

class elf32_phdr(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf64_phdr(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf_dyn(elf):
    """ An elf dynamic section struct"""
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 0, "elf32_dyn", "elf64_dyn", theType, offset, vm, name, **kwargs)    

class elf32_dyn(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf64_dyn(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf_note(elf):
    """An ELF note header"""
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 0, "elf32_note", "elf64_note", theType, offset, vm, name = None, **kwargs)    
   
    def cast_descsz(self, obj_type):
        """Cast the descsz member as a specified type. 
       
        @param obj_type: name of the object 
        
        The descsz member is at a variable offset, which depends
        on the length of the namesz string which precedes it. The
        string is 8-byte aligned and can be zero. 
        """
        
        desc_offset = (self.obj_offset + 
                       self.obj_vm.profile.get_obj_size(self._get_typename("note")) + 
                       ((((self.n_namesz - 1) >> 3) + 1) << 3))
                       
        return obj.Object(obj_type, offset = desc_offset, vm = self.obj_vm, parent = self)    

class elf32_note(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf64_note(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf_link_map(elf):
    """ An libdl link map structure"""
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 0, "elf32_link_map", "elf64_link_map", theType, offset, vm, name, **kwargs)    

    @property
    def l_name(self):
        saddr = self.__getattr__("l_name")
        buf = self.obj_vm.read(saddr, 256)
        idx = buf.find("\x00")
        if idx != -1:
            buf = buf[:idx]
        return str(buf)

    @property
    def l_next(self):
        naddr = self.elf_obj.m("l_next")
        tname = "elf_link_map"
        return obj.Object(tname, offset = naddr, vm = self.obj_vm, parent = self)

    def __iter__(self):
        cur = self
        while cur.is_valid():
            yield cur
            cur = cur.l_next

class elf32_link_map(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf64_link_map(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class ELFModification(obj.ProfileModification):
    def modification(self, profile):
        profile.object_classes.update({
                    'elf'      : elf,
                    'elf_hdr'  : elf_hdr, 
                    'elf_note' : elf_note,
                    'elf_phdr' : elf_phdr,
                    'elf32_phdr' : elf32_phdr,
                    'elf64_phdr' : elf64_phdr,
                    'elf_dyn'    : elf_dyn,
                    'elf32_dyn'  : elf32_dyn,
                    'elf64_dyn'  : elf64_dyn,
                    'elf_note'   : elf_note,
                    'elf64_note' : elf64_note,
                    'elf_link_map'   : elf_link_map,
                    'elf32_link_map' : elf32_link_map,
                    'elf64_link_map' : elf64_link_map,
                    })

class ELF64Modification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(elf64_vtypes)

class ELF32Modification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(elf32_vtypes)
