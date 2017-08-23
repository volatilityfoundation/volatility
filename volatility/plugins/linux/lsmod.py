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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import re, os, struct
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_lsmod(linux_common.AbstractLinuxCommand):
    """Gather loaded kernel modules"""

    def __init__(self, config, *args, **kwargs):

        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
      
        self._config.add_option('SECTIONS', short_option = 'T', default = None, help = 'show section addresses', action = 'store_true')
        self._config.add_option('PARAMS', short_option = 'P', default = None, help = 'show module parameters', action = 'store_true')
        self._config.add_option('BASE', short_option = 'b', default = None, help = 'Dump driver with BASE address (in hex)', action = 'store', type = 'int')
        self._config.add_option('IDC', short_option = 'c', default = None, help = 'Path to IDC file to be created for module', action = 'store', type = 'str')
        

    def _get_modules(self):
        if self._config.BASE:
            module_address = int(self._config.BASE)
            yield obj.Object("module", offset = module_address, vm = self.addr_space)
        else:
            modules_addr = self.addr_space.profile.get_symbol("modules")

            modules = obj.Object("list_head", vm = self.addr_space, offset = modules_addr)

            # walk the modules list
            for module in modules.list_of_type("module", "list"):
                yield module

    def calculate(self):
        linux_common.set_plugin_members(self)
        
        for module in self._get_modules():
            if self._config.PARAMS:
                if not hasattr(module, "kp"):
                    debug.error("Gathering module parameters is not supported in this profile.")

                params = module.get_params()
            else:
                params = ""

            if self._config.SECTIONS:
                sections = module.get_sections()
            else:
                sections = []

            yield (module, sections, params)

    def render_text(self, outfd, data):

        for (module, sections, params)  in data:
            if self._config.IDC:
                fd = open(self._config.IDC, "w")
                fd.write("#include <idc.idc>\nstatic main(void) {\n")
                
                for (sname, saddr) in module.get_symbols():             
                    fd.write("   MakeDword(0x{0:08X});\n".format(saddr))
                    fd.write("   MakeName(0x{0:08X}, \"{1}\");\n".format(saddr, sname))

                fd.write("}")

            outfd.write("{2:x} {0:s} {1:d}\n".format(module.name, module.init_size + module.core_size, module.obj_offset))

            # will be empty list if not set on command line
            for sect in sections:
                outfd.write("\t{0:30s} {1:#x}\n".format(sect.sect_name, sect.address))

            # will be "" if not set, otherwise will be space seperated
            if params != "":
                for param in params.split():
                    outfd.write("\t{0:100s}\n".format(param))

    def get_module(self, name):
        ret = None

        for (module, _, _) in self.calculate():
            if str(module.name) == name:
                ret = module
                break

        return ret

    # returns a list of tuples of (name, .text start, .text end) for each module
    # include_list can contain a list of only the modules wanted by a plugin
    def get_modules(self, include_list = None):
        if not include_list:
            include_list = []

        ret = []
        for (module, _sections, _params) in self.calculate():

            if len(include_list) == 0 or str(module.name) in include_list:

                start = module.module_core
                end = start + module.core_size
                ret.append(("%s" % module.name, start, end))

        return ret

class linux_moddump(linux_common.AbstractLinuxCommand):
    """Extract loaded kernel modules"""
    
    def __init__(self, config, *args, **kwargs):
        self.name_idx = 1
        self.idc_started = False

        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        
        config.add_option('DUMP-DIR', short_option = 'D', default = None,       
                      help = 'Directory in which to dump the files',
                      action = 'store', type = 'string')
        config.add_option('REGEX', short_option = 'r',
                      help = 'Dump modules matching REGEX',
                      action = 'store', type = 'string')
        config.add_option('IGNORE-CASE', short_option = 'i',
                      help = 'Ignore case in pattern match',
                      action = 'store_true', default = False)
        config.add_option('BASE', short_option = 'b', default = None,
                          help = 'Dump driver with BASE address (in hex)',
                          action = 'store', type = 'int')

    def calculate(self):
        linux_common.set_plugin_members(self)

        if self._config.REGEX:
            try:
                if self._config.IGNORE_CASE:
                    mod_re = re.compile(self._config.REGEX, re.I)
                else:
                    mod_re = re.compile(self._config.REGEX)
            except re.error, e:
                debug.error('Error parsing regular expression: {0}'.format(e))
                

        if self._config.BASE:
            module_address = int(self._config.BASE)
            yield obj.Object("module", offset = module_address, vm = self.addr_space)
        else:
            # walk the modules list
            modules_addr = self.addr_space.profile.get_symbol("modules")
            modules = obj.Object("list_head", vm = self.addr_space, offset = modules_addr)
            for module in modules.list_of_type("module", "list"):
                if self._config.REGEX:
                    if not mod_re.search(str(module.name)):
                        continue
                yield module
    
    def _get_header_64(self, load_addr, sect_hdr_offset, num_sects):
        e_ident     = "\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        e_type      = "\x01\x00" # relocateble
        e_machine   = "\x03\x00"
        e_version   = "\x01\x00\x00\x00"
        e_entry     = "\x00" * 8
        e_phoff     = "\x00" * 8
        e_shoff     = struct.pack("<Q", sect_hdr_offset)
        e_flags     = "\x00\x00\x00\x00"
        e_ehsize    = "\x40\x00"
        e_phentsize = "\x00\x00"
        e_phnum     = "\x00\x00"
        e_shentsize = "\x40\x00"
        e_shnum     = struct.pack("<H", num_sects + 1) # this works as we stick the seciton we create at the end
        e_shstrndx  = struct.pack("<H", num_sects)

        header = e_ident + e_type + e_machine + e_version + e_entry + e_phoff + e_shoff + e_flags
    
        header = header + e_ehsize + e_phentsize + e_phnum + e_shentsize + e_shnum + e_shstrndx

        if len(header) != 64:
            debug.error("BUG: ELF header not bytes. %d" % len(header))

        return header

    def _get_header_32(self, load_addr, sect_hdr_offset, num_sects):
        e_ident     = "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        e_type      = "\x01\x00" # relocateble
        e_machine   = "\x03\x00"
        e_version   = "\x01\x00\x00\x00"
        e_entry     = "\x00" * 4
        e_phoff     = "\x00" * 4
        e_shoff     = struct.pack("<I", sect_hdr_offset)
        e_flags     = "\x00\x00\x00\x00"
        e_ehsize    = "\x34\x00"
        e_phentsize = "\x00\x00"
        e_phnum     = "\x00\x00"
        e_shentsize = "\x28\x00"
        e_shnum     = struct.pack("<H", num_sects + 1) # this works as we stick the seciton we create at the end
        e_shstrndx  = struct.pack("<H", num_sects)

        header = e_ident + e_type + e_machine + e_version + e_entry + e_phoff + e_shoff + e_flags
    
        header = header + e_ehsize + e_phentsize + e_phnum + e_shentsize + e_shnum + e_shstrndx

        if len(header) != 52:
            debug.error("BUG: ELF header not bytes. %d" % len(header))

        return header

    # checked
    def _build_sections_list(self, module):
        sections = []
        
        symtab_idx = -1

        for (i, sect) in enumerate(module.get_sections()):
            name = str(sect.sect_name)

            sections.append((name, sect.address.v()))
                         
            if name == ".symtab":
                symtab_idx = i

        if symtab_idx == -1:
            debug.error("No section .symtab found. Unable to properly re-create ELF file.")

        return (sections, symtab_idx)

    # we do this in a couple phases:
    # 1) walk the volatlity get_sections
    # 2) this gives us the name and start address of each
    # 3) we use the list we build in build_.. so then we can calcluate the size of each
    # 4) with the final list of name,address,size we can read the sections and populate the info in the file
    def _parse_sections(self, module):
        (orig_sections, symtab_idx) = self._build_sections_list(module)
       
        if self.addr_space.profile.metadata.get('memory_model', '32bit') == '64bit':
            sect_bytes = 64
        else:
            sect_bytes = 52

        updated_sections = []
        tmp_ents = {}

        for (_i, (name, address)) in enumerate(orig_sections):
            tmp_ents[address] = 1

        addrs = sorted(tmp_ents.keys())
       
        sorted_ents = {}
        for (i, addr) in enumerate(addrs):
            sorted_ents[addr] = i
        
        sect_sa = []
        # do this twice for now... just want the plugin working!
        for (i, (name, address)) in enumerate(orig_sections):
            sort_idx = sorted_ents[address]

            if name == ".symtab":
                str_section_data = self._fix_sym_table(module, sect_sa)
                str_size = len(str_section_data)
                size = str_size
            else:
                try:
                    next_addr = addrs[sort_idx+1]
                    size = next_addr - address
                except IndexError:
                    # the last one
                    size = 0x4000 # guess?

            sect_sa.append((name, address, size))

        for (i, (name, address)) in enumerate(orig_sections):
            sort_idx = sorted_ents[address]

            try:
                next_addr = addrs[sort_idx+1]
                size = next_addr - address
            except IndexError:
                # the last one
                size = 0x4000 # guess?

            if name == ".symtab":
                size         = str_size
                section_data = str_section_data
            else:  
                section_data = module.obj_vm.zread(address, size)

            updated_sections.append((name, address, size, sect_bytes, section_data))
            
            sect_bytes = sect_bytes + size
       
        return (updated_sections, symtab_idx, addrs[0])

    def _calc_sect_name_idx(self, name):
        ret = self.name_idx
        self.name_idx = self.name_idx + len(name) + 1
        return ret

    def _calc_sect_type(self, name):
        type_map = {
            "SHT_NULL" : 0,
            "SHT_PROGBITS" : 1,
            "SHT_SYMTAB" : 2,
            "SHT_STRTAB" : 3,
            "SHT_RELA" : 4,
            "SHT_HASH" : 5,
            "SHT_DYNAMIC" : 6,
            "SHT_NOTE" : 7,
            "SHT_NOBITS" : 8,
            "SHT_REL" : 9,
            "SHT_SHLIB" : 10,
            "SHT_DYNSYM" : 11,
            "SHT_LOPROC" : 0x70000000,
            "SHT_HIPROC" : 0x7fffffff,
            "SHT_LOUSER" : 0x80000000,
            "SHT_HIUSER" : 0xffffffff
        }
         
        known_sections = {
            ".note.gnu.build-id" : "SHT_NOTE",
            ".text"              : "SHT_PROGBITS",
            ".rodata"            : "SHT_PROGBITS",
            ".modinfo"           : "SHT_PROGBITS",
            "__param"            : "SHT_PROGBITS",
            ".data"              : "SHT_PROGBITS",
            ".gnu.linkonce.this_module" : "SHT_PROGBITS",
            ".comment"                  : "SHT_PROGBITS",
            ".shstrtab"                 : "SHT_STRTAB",
            ".symtab"                   : "SHT_SYMTAB",
            ".strtab"                   : "SHT_STRTAB",
            } 

        if name in known_sections:
            sect_type_name = known_sections[name]
            sect_type_val  = type_map[sect_type_name]
        else:
            sect_type_val = 1 # SHT_PROGBITS
         
        if name.find(".rela.") != -1:
            sect_type_val = 4 # SHT_RELA

        return sect_type_val

    # all sections from memory are allocated (SHF_ALLOC)
    # special check certain other sections to try and ensure extra flags are added where needed
    def _calc_sect_flags(self, name):
        flags = 2 # SHF_ALLOC
        
        if name == ".text":
            flags = flags | 4 # SHF_EXECINSTR
        
        elif name in [".data", ".bss"]:
            flags = flags | 1 # SHF_WRITE

        return flags

    def _calc_link(self, name, strtab_idx, symtab_idx, sect_type):
        # looking for RELA sections
        if name.find(".rela.") != -1: 
            lnk = strtab_idx

        elif sect_type == 2: # strtab
            lnk = strtab_idx

        else:
            lnk = 0

        return lnk

    def _calc_entsize(self, name, sect_type, bits):
        # looking for RELA sections
        if name.find(".rela.") != -1: 
            info = 24

        elif sect_type == 2: # symtab
            if bits == 32:
                info = 16
            else:
                info = 24
        else:
            info = 0

        return info
    
    def _make_sect_header_64(self, name, address, size, file_off, strtab_idx, symtab_idx):
        int_sh_type = self._calc_sect_type(name)

        sh_name       = struct.pack("<I", self._calc_sect_name_idx(name))
        sh_type       = struct.pack("<I", int_sh_type)
        sh_flags      = struct.pack("<Q", self._calc_sect_flags(name))
        sh_addr       = struct.pack("<Q", address)
        sh_offset     = struct.pack("<Q", file_off)
        sh_size       = struct.pack("<Q", size)
        sh_link       = struct.pack("<I", self._calc_link(name, strtab_idx, symtab_idx, int_sh_type))
        sh_info       = "\x00" * 4 
        sh_addralign  = "\x01\x00\x00\x00\x00\x00\x00\x00"
        sh_entsize    = struct.pack("<Q", self._calc_entsize(name, int_sh_type, 64))
   
        data = sh_name + sh_type + sh_flags + sh_addr + sh_offset + sh_size
        data = data + sh_link + sh_info + sh_addralign + sh_entsize
 
        if len(data) != 64:
            debug.error("Broken section building! %d" % len(data))

        return data

    def _make_sect_header_32(self, name, address, size, file_off, strtab_idx, symtab_idx):
        int_sh_type = self._calc_sect_type(name)

        sh_name       = struct.pack("<I", self._calc_sect_name_idx(name))
        sh_type       = struct.pack("<I", int_sh_type)
        sh_flags      = struct.pack("<I", self._calc_sect_flags(name))
        sh_addr       = struct.pack("<I", address)
        sh_offset     = struct.pack("<I", file_off)
        sh_size       = struct.pack("<I", size)
        sh_link       = struct.pack("<I", self._calc_link(name, strtab_idx, symtab_idx, int_sh_type))
        sh_info       = "\x00" * 4 
        sh_addralign  = "\x01\x00\x00\x00"
        sh_entsize    = struct.pack("<I", self._calc_entsize(name, int_sh_type, 32))
   
        data = sh_name + sh_type + sh_flags + sh_addr + sh_offset + sh_size
        data = data + sh_link + sh_info + sh_addralign + sh_entsize
 
        if len(data) != 40:
            debug.error("Broken section building! %d" % len(data))

        return data

    def _null_sect_hdr(self, sz):
        return "\x00" * sz

    # the shstrtab section is "\x00\x2e" + section name for each section
    def _calc_string_data(self, module):
        data = ""

        for sect in module.get_sections():
            data = data + "\x00" + str(sect.sect_name)

        # put in our added section name + null terminator for section
        data = data + "\x00.shstrtab" + "\x00"

        return data              

    def _find_sec(self, sections_info, sym_addr):
        for sect in sections_info:
            (name, address, size) = sect
            
            if address <= sym_addr < address + size:
                return name

        return ""

    def _fix_sym_table(self, module, sections_info):
        all_sym_data = ""
        
        first_name = False

        if self.addr_space.profile.metadata.get('memory_model', '32bit') == '64bit':
            sym_type     = "elf64_sym"
            st_value_fmt = "<Q"
            st_size_fmt  = "<Q"
        else:
            sym_type     = "elf32_sym"
            st_value_fmt = "<I"
            st_size_fmt  = "<I"
              
        val_map      = {}
        name_idx_map = {}
        syms = obj.Object(theType="Array", targetType=sym_type, count=module.num_symtab, vm = module.obj_vm, offset = module.symtab)
        for (e, sym) in enumerate(syms):
            if sym.st_value > 0 and not module.obj_vm.profile.get_symbol_by_address("kernel", sym.st_value):
                val_map[sym.st_value.v()] = self._find_sec(sections_info, sym.st_value) 
                

        for (i, sect) in enumerate(module.get_sections()):
            name_idx_map[str(sect.sect_name)] = (i + 1, sect.address) ### account for null segment
      
        syms = obj.Object(theType="Array", targetType=sym_type, count=module.num_symtab, vm = module.obj_vm, offset = module.symtab)
        for sym in syms:
            # fix absolute addresses  
            st_value_int = sym.st_value.v()
            if st_value_int > 0 and st_value_int in val_map:
                secname = val_map[st_value_int]
                if secname in name_idx_map:
                    sect_addr = name_idx_map[secname][1]
                    # LOOK_HERE
                    st_value_sub  = st_value_int - sect_addr 
                    st_value_full = st_value_int
            
            else:
                st_value_sub  = st_value_int
                st_value_full = st_value_int
            
            st_value = struct.pack(st_value_fmt, st_value_sub)

            #### fix bindings ####
                
            # moved out of the sections part
            if sym.st_name > 0:
                first_name = True   
         
            if first_name:
                bind = 1 # STB_GLOBAL

                if sym.st_value == 0:
                    stype = 0

                elif module.obj_vm.profile.get_symbol_by_address("kernel", sym.st_value):
                    stype = 0 # STT_NOTYPE

                else:
                    secname = val_map[sym.st_value.v()]

                    # a .text. section but not relocations
                    if secname.find(".text") != -1 and secname.find(".rela") == -1:
                        stype = 2 # STT_FUNC                        
                    else:
                        stype = 1 # STT_OBJECT
            else: 
                bind  = 0 # STB_LOCAL
                stype = 3 # STT_SECTION

            b = (bind << 4) & 0xf0
            t = stype & 0xf
            st_info = (b | t) & 0xff
            st_info = struct.pack("B", st_info)
            
            #### fix indexes ####
            if sym.st_value > 0 and sym.st_value.v() in val_map:
                secname = val_map[sym.st_value.v()]
                if secname in name_idx_map:
                    st_shndx = name_idx_map[secname][0]
                    st_shndx = struct.pack("<H", st_shndx)
                elif not secname:
                    st_shndx = struct.pack("<H", sym.st_shndx)
                else:
                    debug.error("no index for %s" % secname)
            else:
                st_shndx = struct.pack("<H", sym.st_shndx)

            ######

            # ones that aren't mangled
            st_name  = struct.pack("<I", sym.st_name)
            st_other = struct.pack("B", sym.st_other)
            st_size  = struct.pack(st_size_fmt, sym.st_size)        
   
            if sym_type == "elf64_sym": 
                sec_all = st_name + st_info + st_other + st_shndx + st_value + st_size
                sec_len = 24 

            else:
                sec_all = st_name + st_value + st_size + st_info + st_other + st_shndx
                sec_len = 16

            if len(sec_all) != sec_len:
                debug.error("Invalid section length: %d" % len(sec_all))

            all_sym_data = all_sym_data + sec_all        

        return all_sym_data

    def _get_module_data(self, module):
        (updated_sections, symtab_idx, load_addr) = self._parse_sections(module)
        
        if self.addr_space.profile.metadata.get('memory_model', '32bit') == '64bit':
            hdr_sz = 64
            sect_sz = 64
            _get_header       = self._get_header_64
            _make_sect_header = self._make_sect_header_64
        else:
            hdr_sz = 52
            _get_header       = self._get_header_32
            _make_sect_header = self._make_sect_header_32
            sect_sz = 40

        section_headers = self._null_sect_hdr(sect_sz)
        section_data    = ""

        strtab_idx = len(updated_sections) 

        for (i, (name, address, size, file_off, sect_data)) in enumerate(updated_sections):
            section_headers = section_headers + _make_sect_header(name, address, size, file_off, strtab_idx, symtab_idx)
            
            section_data    = section_data + sect_data              

            last_file_off = file_off
            last_sec_sz   = len(sect_data)

            if len(sect_data) != size:
                return ""

        # we need this section, but its not in memory
        # we can manually create it though and add it to our file
        sdata = self._calc_string_data(module)
        section_headers = section_headers + _make_sect_header(".shstrtab", 0, len(sdata), last_file_off + last_sec_sz, strtab_idx, symtab_idx)
        section_data = section_data + sdata

        # we stick it at the end
        num_sects  = len(updated_sections) + 1
            
        header = _get_header(load_addr - hdr_sz, hdr_sz + len(section_data), num_sects)

        return header + section_data + section_headers 

    def get_module_data(self, module):
        return self._get_module_data(module)

    def render_text(self, outfd, data):
        if not self._config.DUMP_DIR:
            debug.error("You must supply a --dump-dir output directory")
        
        for module in data:
            ## TODO: pass module.name through a char sanitizer 
            file_name = "{0}.{1:#x}.lkm".format(module.name, module.obj_offset)
            mod_file = open(os.path.join(self._config.DUMP_DIR, file_name), 'wb')
            mod_data = self.get_module_data(module)
            mod_file.write(mod_data)
            mod_file.close()
            outfd.write("Wrote {0} bytes to {1}\n".format(len(mod_data), file_name))

