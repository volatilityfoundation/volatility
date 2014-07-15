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
        'sh_entsize'   : [36, ['unsigned int']],
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

    'elf32_sym' : [ 16, {
        'st_name'   : [ 0,  ['unsigned int']],
        'st_value'  : [ 4,  ['unsigned int']],
        'st_size'   : [ 8,  ['unsigned int']],
        'st_info'   : [ 12, ['unsigned char']],
        'st_other'  : [ 13, ['unsigned char']],
        'st_shndx'  : [ 14,  ['unsigned short']],
    }],

    'elf32_rel' : [ 8, {
        'r_offset' : [ 0,  ['unsigned int']],
        'r_info'   : [ 4,  ['unsigned int']],
    }],

    'elf32_rela' : [ 12, {
        'r_offset' : [ 0,  ['unsigned int']],
        'r_info'   : [ 4,  ['unsigned int']],
        'r_addend' : [ 8,  ['int']],
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
        'sh_entsize'   : [56, ['unsigned long long']],
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
    
    'elf64_sym' : [ 24 , {
        'st_name'  : [ 0, ['unsigned int']],
        'st_info'  : [ 4, ['unsigned char']],
        'st_other' : [ 5, ['unsigned char']],
        'st_shndx' : [ 6, ['unsigned short']],
        'st_value' : [ 8, ['unsigned long long']],
        'st_size'  : [ 16, ['unsigned long long']],
    }],

    'elf64_link_map' : [0, {
        'l_addr' : [0, ['unsigned long long']], 
        'l_name' : [8, ['unsigned long long']], 
        'l_ld'   : [16, ['unsigned long long']], 
        'l_next' : [24, ['unsigned long long']], 
        'l_prev' : [32, ['unsigned long long']], 
    }],
   
    'elf64_rel' : [ 16, {
        'r_offset' : [ 0,  ['unsigned long long']],
        'r_info'   : [ 8,  ['unsigned long long']],
    }],

    'elf64_rela' : [ 24, {
        'r_offset' : [ 0,  ['unsigned long long']],
        'r_info'   : [ 8,  ['unsigned long long']],
        'r_addend' : [ 16,  ['long long']],
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
    
    def is_valid(self):
        return self.size_cache in [32, 64, -39]

    def _init_cache_from_parent(self):
        self.size_cache = self.obj_parent.size_cache
        
        self._make_elf_obj(self.obj_offset, self.obj_vm)

    def _make_elf_obj(self, offset, vm):
        if self.size_cache == 32:
            self.elf_obj = obj.Object(self.name32, offset = offset, vm = vm)
        elif self.size_cache == 64:
            self.elf_obj = obj.Object(self.name64, offset = offset, vm = vm)
        else:
            self.elf_obj = None
        
    def _set_size_cache(self, offset, vm):
        ei_class = obj.Object("unsigned char", offset = offset + 4, vm = vm)
        if ei_class == 1:
            self.size_cache = 32
        elif ei_class == 2:
            self.size_cache = 64
        else:
            self.size_cache = -42

    def _init_cache(self, offset, vm):
        self._set_size_cache(offset, vm)
        self._make_elf_obj(offset, vm) 

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
        # these are populaed on the first call to symbols()
        self.cached_symtab  = None
        self.cached_strtab  = None
        self.cached_numsyms = 0

        elf.__init__(self, 1, "elf32_hdr", "elf64_hdr", theType, offset, vm, name, **kwargs)    

    def is_valid(self):
        return self.elf_obj != None
        
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
            if phdr.is_valid():
                yield phdr  

    def _section_headers(self):
        rtname = self._get_typename("shdr")
        rtsize = self.obj_vm.profile.get_obj_size(rtname)

        tname = "elf_shdr"
       
        # the buffer of headers
        arr_start = self.obj_offset + self.e_shoff

        return (arr_start, rtsize)

    def section_header(self, idx):
        (arr_start, rtsize) = self._section_headers()
        idx = idx * rtsize
        shdr = obj.Object("elf_shdr", offset = arr_start + idx, vm = self.obj_vm, parent = self)
        return shdr
    
    def section_headers(self):
        (arr_start, rtsize) = self._section_headers()
        for i in range(self.e_shnum):
            # use the real size
            idx = i * rtsize

            shdr = obj.Object("elf_shdr", offset = arr_start + idx, vm = self.obj_vm, parent = self)
            if shdr.is_valid():
                yield shdr  

    def _find_symbols_program_headers(self):
        for phdr in self.program_headers():
            if not phdr.is_valid() or str(phdr.p_type) != 'PT_DYNAMIC':
                continue                   
    
            dt_strtab = None
            dt_symtab = None    
            dt_strent = None

            for dsec in phdr.dynamic_sections():
                if dsec.d_tag == 5:
                    dt_strtab = dsec.d_ptr

                elif dsec.d_tag == 6:
                    dt_symtab = dsec.d_ptr

                elif dsec.d_tag == 11:
                    dt_strent = dsec.d_ptr

            if dt_strtab == None or dt_symtab == None or dt_strent == None:
                return None
            
            break

        self.cached_symtab  = dt_symtab
        self.cached_strtab  = dt_strtab

        if dt_symtab.v() < dt_strtab.v():
            self.cached_numsyms = (dt_strtab.v() - dt_symtab.v()) / dt_strent 
        else:
            self.cached_numsyms = 1024
    
    def _find_symbols(self):
        self._find_symbols_program_headers()

    def symbols(self):
        if self.cached_symtab == None:
            self._find_symbols()
                
        if self.cached_symtab == None:
            return

        rtname = self._get_typename("sym")

        symtab_arr = obj.Object(theType="Array", targetType=rtname, count=self.cached_numsyms, offset = self.cached_symtab, vm = self.obj_vm) 
        for sym in symtab_arr:
            yield sym

    def symbol_at(self, sym_idx):
        ret = None

        for (cur_idx, sym) in enumerate(self.symbols()):
            if cur_idx == sym_idx:
                ret = sym
                break

        return ret            

    def symbol_name(self, sym):
        addr = self.cached_strtab + sym.st_name
        name = self.obj_vm.read(addr, 255)
        if name:
            idx = name.find("\x00")
            if idx != -1:
                name = name[:idx]
        else:
            name = "N/A"
        return name

    def relocation_symbol(self, reloc):
        ridx = reloc.relocation_symbol_index()
        sym = self.symbol_at(ridx)
        return sym

    def relocations(self):
        for phdr in self.program_headers():
            if str(phdr.p_type) != 'PT_DYNAMIC':
                continue
            
            dt_jmprel   = None
            dt_pltrelsz = None
            dt_pltrel   = None

            for dsec in phdr.dynamic_sections():
                if dsec.d_tag == 23:
                    dt_jmprel = dsec.d_ptr

                elif dsec.d_tag == 2:
                    dt_pltrelsz = dsec.d_ptr

                elif dsec.d_tag == 20:
                    dt_pltrel = dsec.d_ptr                  

            if dt_jmprel == None or dt_pltrelsz == None or dt_pltrel == None:
                print "needed info missing"
                return

            if dt_pltrel == 7:
                struct_name = "elf_rela"
                if self.size_cache == 32:
                    struct_size = 12                       
                else:
                    struct_size = 24

            elif dt_pltrel == 17:
                struct_name = "elf_rel"
                if self.size_cache == 32:
                    struct_size = 8          
                else:
                    struct_size = 16
            else:   
                print "unknown relocation type: %d" % dt_pltrel

            # arr = obj.Object(theType="Array", targetType=struct_name, parent = self, count = dt_pltrelsz / struct_size, offset = dt_jmprel, vm = self.obj_vm)


            count = dt_pltrelsz / struct_size
            
            for idx in range(count + 24):
                offset = dt_jmprel + (idx * struct_size)

                reloc = obj.Object(struct_name, offset = offset, vm = self.obj_vm, parent = self)              
                    
                yield reloc 

class elf_shdr(elf):
    """ An elf section header """

    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 0, "elf32_shdr", "elf64_shdr", theType, offset, vm, name, **kwargs)    

class elf32_shdr(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf64_shdr(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf_rel(elf):
    """ An elf relocation """

    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 0, "elf32_rel", "elf64_rel", theType, offset, vm, name, **kwargs)    

    def relocation_type(self):
        t = self._get_typename("rel")
        if t == "elf32_rel":
            ret = self.r_info & 0xff
        else:
            ret = self.r_info & 0xffffffff

        return ret

    def relocation_symbol_index(self):
        t = self._get_typename("rel")
        if t == "elf32_rel":
            ret = self.r_info >> 8
        else:
            ret = self.r_info >> 32
   
        return ret

class elf32_rel(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf64_rel(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf_rela(elf):
    """ An elf relocation """

    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 0, "elf32_rela", "elf64_rela", theType, offset, vm, name, **kwargs)    

    def relocation_type(self):
        t = self._get_typename("rel")
        if t == "elf32_rel":
            ret = self.r_info & 0xff
        else:
            ret = self.r_info & 0xffffffff

        return ret

    def relocation_symbol_index(self):
        t = self._get_typename("rel")
        if t == "elf32_rel":    
            ret = self.r_info >> 8
        else:
            ret = self.r_info >> 32
    
        return ret


class elf32_rela(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf64_rela(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf_phdr(elf):
    """ An elf program header """

    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 0, "elf32_phdr", "elf64_phdr", theType, offset, vm, name, **kwargs)    

    @property
    def p_vaddr(self):
        ret = self.__getattr__("p_vaddr")

        if self.obj_parent.e_type == 3: # ET_DYN
            ret = self.obj_parent.obj_offset + ret

        return ret

    def dynamic_sections(self):
        # sanity check
        if str(self.p_type) != 'PT_DYNAMIC':
            print "failed sanity check"
            return

        rtname = self._get_typename("dyn")
        rtsize = self.obj_vm.profile.get_obj_size(rtname)

        tname = "elf_dyn"
        
        # the buffer of array starts at elf_base + our virtual address ( offset )
        arr_start = self.p_vaddr

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

class elf_sym(elf):
    """ An elf symbol struct"""
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        elf.__init__(self, 0, "elf32_sym", "elf64_sym", theType, offset, vm, name, **kwargs)    

class elf32_sym(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class elf64_sym(obj.CType):
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
        elf.__init__(self, 0, "elf32_note", "elf64_note", theType, offset, vm, name, **kwargs)    
 
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
        buf = self.obj_vm.zread(saddr, 256)
        idx = buf.find("\x00")
        if idx != -1:
            buf = buf[:idx]
        return str(buf)

    @property
    def l_next(self):
        naddr = self.elf_obj.m("l_next")
        tname = "elf_link_map"
        return obj.Object(tname, offset = naddr, vm = self.obj_vm, parent = self)

    @property
    def l_prev(self):
        naddr = self.elf_obj.m("l_prev")
        tname = "elf_link_map"
        return obj.Object(tname, offset = naddr, vm = self.obj_vm, parent = self)

    def __iter__(self):
        cur = self
        while cur:
            yield cur
            cur = cur.l_next

        cur = self
        while cur:
            yield cur
            cur = cur.l_prev

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
                    'elf_shdr'   : elf_shdr,
                    'elf32_shdr' : elf32_shdr,
                    'elf64_shdr' : elf64_shdr,
                    'elf_sym'    : elf_sym,
                    'elf32_sym'  : elf32_sym,
                    'elf64_sym'  : elf64_sym,
                    'elf_note'   : elf_note,
                    'elf32_note' : elf32_note,
                    'elf64_note' : elf64_note,
                    'elf_link_map'   : elf_link_map,
                    'elf32_link_map' : elf32_link_map,
                    'elf64_link_map' : elf64_link_map,
                    'elf_rel'    : elf_rel, 
                    'elf32_rel'  : elf32_rel, 
                    'elf64_rel'  : elf64_rel,
                    'elf_rela'   : elf_rela,
                    'elf32_rela' : elf32_rela,
                    'elf64_rela' : elf64_rela 
                     })

class ELF64Modification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(elf64_vtypes)

class ELF32Modification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(elf32_vtypes)

