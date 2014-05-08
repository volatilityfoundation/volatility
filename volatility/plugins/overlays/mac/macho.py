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

import volatility.obj as obj

macho_types = {
 'fat_header': [ 0x8, {
    'magic': [0x0, ['unsigned int']],
    'nfat_arch': [0x4, ['unsigned int']],
}],
 'fat_arch': [ 0x14, {
    'cputype': [0x0, ['int']],
    'cpusubtype': [0x4, ['int']],
    'offset': [0x8, ['unsigned int']],
    'size': [0xc, ['unsigned int']],
    'align': [0x10, ['unsigned int']],
}],
 'macho64_header': [ 32, {
    'magic'     : [0,  ['unsigned int']],
    'cputype'   : [4,  ['int']],
    'cpusubtype': [8,  ['int']],
    'filetype'  : [12, ['unsigned int']],
    'ncmds'     : [16, ['unsigned int']],
    'sizeofcmds': [20, ['unsigned int']],
    'flags'     : [24, ['unsigned int']],
    'reserved'  : [28, ['unsigned int']],
}],
 'macho32_header': [ 28, {
    'magic'      : [0,  ['unsigned int']],
    'cputype'    : [4,  ['int']],
    'cpusubtype' : [8,  ['int']],
    'filetype'   : [12, ['unsigned int']],
    'ncmds'      : [16, ['unsigned int']],
    'sizeofcmds' : [20, ['unsigned int']],
    'flags'      : [24, ['unsigned int']],
}],
 'macho32_symtab_command': [ 0x18, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
    'symoff': [0x8, ['unsigned int']],
    'nsyms': [0xc, ['unsigned int']],
    'stroff': [0x10, ['unsigned int']],
    'strsize': [0x14, ['unsigned int']],
}],
 'macho64_symtab_command': [ 0x18, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
    'symoff': [0x8, ['unsigned int']],
    'nsyms': [0xc, ['unsigned int']],
    'stroff': [0x10, ['unsigned int']],
    'strsize': [0x14, ['unsigned int']],
}],
'macho32_load_command': [ 0x8, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
}],
'macho64_load_command': [ 0x8, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
}],
'macho32_segment_command': [ 0x38, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
    'segname': [0x8, ['String', dict(length = 16)]],
    'vmaddr': [0x18, ['unsigned int']],
    'vmsize': [0x1c, ['unsigned int']],
    'fileoff': [0x20, ['unsigned int']],
    'filesize': [0x24, ['unsigned int']],
    'maxprot': [0x28, ['int']],
    'initprot': [0x2c, ['int']],
    'nsects': [0x30, ['unsigned int']],
    'flags': [0x34, ['unsigned int']],
}],
'macho64_segment_command': [ 0x48, {
    'cmd': [0x0, ['unsigned int']],
    'cmdsize': [0x4, ['unsigned int']],
    'segname': [0x8, ['String', dict(length = 16)]],
    'vmaddr': [0x18, ['unsigned long long']],
    'vmsize': [0x20, ['unsigned long long']],
    'fileoff': [0x28, ['unsigned long long']],
    'filesize': [0x30, ['unsigned long long']],
    'maxprot': [0x38, ['int']],
    'initprot': [0x3c, ['int']],
    'nsects': [0x40, ['unsigned int']],
    'flags': [0x44, ['unsigned int']],
}],
 'macho64_section': [ 0x50, {
    'sectname': [0x0, ['array', 16, ['char']]],
    'segname': [0x10, ['array', 16, ['char']]],
    'addr': [0x20, ['unsigned long long']],
    'size': [0x28, ['unsigned long long']],
    'offset': [0x30, ['unsigned int']],
    'align': [0x34, ['unsigned int']],
    'reloff': [0x38, ['unsigned int']],
    'nreloc': [0x3c, ['unsigned int']],
    'flags': [0x40, ['unsigned int']],
    'reserved1': [0x44, ['unsigned int']],
    'reserved2': [0x48, ['unsigned int']],
    'reserved3': [0x4c, ['unsigned int']],
}],
 'macho32_section': [ 0x44, {
    'sectname': [0x0, ['array', 16, ['char']]],
    'segname': [0x10, ['array', 16, ['char']]],
    'addr': [0x20, ['unsigned int']],
    'size': [0x24, ['unsigned int']],
    'offset': [0x28, ['unsigned int']],
    'align': [0x2c, ['unsigned int']],
    'reloff': [0x30, ['unsigned int']],
    'nreloc': [0x34, ['unsigned int']],
    'flags': [0x38, ['unsigned int']],
    'reserved1': [0x3c, ['unsigned int']],
    'reserved2': [0x40, ['unsigned int']],
}],
 'macho32_nlist': [ 12, {
    'n_strx' : [0,  ['unsigned int']],
    'n_type' : [4,  ['unsigned char']],
    'n_sect' : [5,  ['unsigned char']],
    'n_desc' : [6, ['unsigned short']],
    'n_value': [8, ['unsigned int']],
}],

 'macho64_nlist': [ 16, {
    'n_strx' : [0,  ['unsigned int']],
    'n_type' : [4,  ['unsigned char']],
    'n_sect' : [5,  ['unsigned char']],
    'n_desc' : [6, ['unsigned short']],
    'n_value': [8, ['unsigned long long']],
}],


}

class macho(obj.CType):
    def __init__(self, is_header, name32, name64, theType, offset, vm, name = None, **kwargs):  
        self.name32 = name32
        self.name64 = name64
        self.macho_obj = None

        if is_header:
            self._init_cache(offset, vm)
        else:
            self.size_cache = -39

        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)
    
    def is_valid(self):
        return self.size_cache in [32, 64, -39]

    def _init_cache(self, offset, vm):
        self._set_size_cache(offset, vm)
        self._make_macho_obj(offset, vm) 

    def _init_cache_from_parent(self):
        self.size_cache = self.obj_parent.size_cache
        self._make_macho_obj(self.obj_offset, self.obj_vm)

    def _make_macho_obj(self, offset, vm):
        if self.size_cache == 32:
            self.macho_obj = obj.Object(self.name32, offset = offset, vm = vm)
        elif self.size_cache == 64:
            self.macho_obj = obj.Object(self.name64, offset = offset, vm = vm)
        else:
            self.macho_obj = None

    def _set_size_cache(self, offset, vm):
        ei_class = obj.Object("unsigned int", offset = offset + 4, vm = vm)
        if ei_class == 7: # CPU_TYPE_I386 / CPU_TYPE_X86
            self.size_cache = 32
        elif ei_class == 0x1000007: # CPU_TYPE_X86_64
            self.size_cache = 64
        else:
            self.size_cache = -42

    def _get_typename(self, typename):
        if self.size_cache == -39:
            self._init_cache_from_parent()

        if self.size_cache == 32:
            typename = "macho32_" + typename
        else:
            typename = "macho64_" + typename

        return typename

    def __getattr__(self, attr):
        if self.size_cache == -39:
            self._init_cache_from_parent()

        return self.macho_obj.__getattr__(attr)

class macho_header(macho):
    """An macho header"""
    
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        # these are populaed on the first call to symbols()
        self.cached_strtab  = None
        self.cached_syms    = None
        self.cached_numsyms = 0

        macho.__init__(self, 1, "macho32_header", "macho64_header", theType, offset, vm, name, **kwargs)    

    def load_commands(self):
        rtname = self._get_typename("load_command")
        rtsize = self.obj_vm.profile.get_obj_size(rtname)

        tname = "macho_load_command"
        
        # the load commands start after the header
        hdr_size = self.macho_obj.size()
         
        arr_start = self.obj_offset + hdr_size

        offset = 0

        for i in range(self.ncmds):
            cmd = obj.Object(tname, offset = arr_start + offset, vm = self.obj_vm, parent = self)

            yield cmd

            offset = offset + cmd.cmdsize
    
    def load_commands_of_type(self, cmd_type):
        cmds = []

        for cmd in self.load_commands():
            if cmd_type == cmd.cmd.v():
                cmds.append(cmd)

        return cmds

    def load_command_of_type(self, cmd_type):
        ret = None

        cmds = self.load_commands_of_type(cmd_type)
        if cmds and len(cmds) > 1:
            debug.error("load_command_of_type: Multiple commands of type %d found!" % cmd_type)
        else:
            ret = cmds[0]

        return ret
    
    # used to fill the cache of symbols
    def _get_syms(self, sym_cmd):
        syms = []
        
        sym_type = self._get_typename("nlist")

        print "macho: %x symoff: %x" % (self.obj_offset, sym_cmd.symoff)

        sym_arr = obj.Object(theType="Array", targetType=sym_type, count=sym_cmd.nsyms, offset = self.obj_offset + sym_cmd.symoff, vm = self.obj_vm)

        for sym in sym_arr:
            syms.append(sym)

        return syms

    def _build_symbol_caches(self):
        symtab_cmd = self.load_command_of_type(2) # LC_SYMTAB
        
        struct_name = self._get_typename("symtab_command")
    
        symtab_command = symtab_cmd.cast(struct_name)

        self.cached_strtab  = self.obj_offset + symtab_command.stroff
        self.cached_numsyms = symtab_command.nsyms
        self.cached_syms    = self._get_syms(symtab_command) 

    def symbols(self):
        if self.cached_strtab == None:
            self._build_symbol_caches()        

        return self.cached_syms         
 
    def symbol_name(self, sym):
        if self.cached_strtab == None:
            self._build_symbol_caches()        
         
        name_addr = self.cached_strtab + sym.n_strx
        
        print "strab: %x name_addr: %x" % (self.cached_strtab, sym.n_strx)

        name = self.obj_vm.read(name_addr, 128)
        if name:
            idx = name.find("\x00")
            if idx != -1:
                name = name[:idx]

        return name 

    def address_for_symbol(self, sym_name):
        ret = None

        for sym in self.symbols():
            if self.symbol_name(sym) == sym_name:
                ret = sym.n_value.v()
                break

        return ret

    def segments(self):
        seg_struct = self._get_typename("segment_command")

        LC_SEGMENT    = 1    # 32 bit segments
        LC_SEGMENT_64 = 0x19 # 64 bit segments

        if self.size_cache == 32:
            seg_type = LC_SEGMENT
        else:
            seg_type = LC_SEGMENT_64

        load_commands = self.load_commands_of_type(seg_type) 

        for load_command in load_commands:
            segment = load_command.cast(seg_struct)

            yield segment

    def get_segment(self, segment_name):
        ret = None   
            
        for segment in self.get_segments():
            if str(segment.segname) == segment_name:
                ret = segment
                break

        return ret
    
    def sections_for_segment(self, segment):
        sect_struct = self._get_typename("section")
        seg_size = segment.size()

        sect_array = obj.Object(theType="Array", targetType=sect_struct, offset=segment.obj_offset + seg_size, count=segment.nsects, vm = self.obj_vm) 

        for sect in sect_array:
            yield sect

class macho32_header(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho64_header(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho_section(macho):
    """ An macho section header """
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        macho.__init__(self, 0, "macho32_section", "macho64_section", theType, offset, vm, name, **kwargs)    

class macho32_section(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho64_section(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho_segment_command(macho):
    """ A macho segment command """
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        macho.__init__(self, 0, "macho32_segment_command", "macho64_segment_command", theType, offset, vm, name, **kwargs)    

class macho32_segment_command(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho64_segment_command(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho_load_command(macho):
    """ A macho load command """
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        macho.__init__(self, 0, "macho32_load_command", "macho64_load_command", theType, offset, vm, name, **kwargs)    

    @property
    def cmd_type(self):
        cmd_types = {
                    1  : "LC_SEGMENT",
                    2  : "LC_SYMTAB",
                    25 : "LC_SEGMENT_64",
                    12 : "LC_LOAD_DYLIB",
                    }

        cmd = self.cmd.v()
        if cmd in cmd_types:
            ret = cmd_types[cmd]
        else:
            ret = ""
    
        return ret

class macho32_load_command(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho64_load_command(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho_symtab_command(macho):
    """ A macho symtab command """
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        macho.__init__(self, 0, "macho32_symtab_command", "macho64_symtab_command", theType, offset, vm, name, **kwargs)    

class macho32_symtab_command(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho64_symtab_command(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho_nlist(macho):
    """ A macho nlist """
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        macho.__init__(self, 0, "macho32_nlist", "macho64_nlist", theType, offset, vm, name, **kwargs)    

class macho32_nlist(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class macho64_nlist(obj.CType):
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)

class MachoTypes(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(macho_types)

class MachoModification(obj.ProfileModification):
    def modification(self, profile):
        profile.object_classes.update({
                    'macho'                   : macho,
                    'macho_header'            : macho_header,
                    'macho32_header'          : macho32_header,
                    'macho64_header'          : macho64_header,
                    'macho_section'           : macho_section, 
                    'macho32_section'         : macho32_section, 
                    'macho64_section'         : macho64_section, 
                    'macho_segment_command'   : macho_segment_command,
                    'macho32_segment_command' : macho32_segment_command,
                    'macho64_segment_command' : macho64_segment_command,
                    'macho_load_command'      : macho_load_command,
                    'macho32_load_command'    : macho32_load_command,
                    'macho64_load_command'    : macho64_load_command,
                    'macho_symtab_command'    : macho_symtab_command,
                    'macho32_symtab_command'  : macho32_symtab_command,
                    'macho64_symtab_command'  : macho64_symtab_command,
                    'macho_nlist'             : macho_nlist,
                    'macho32_nlist'           : macho32_nlist,
                    'macho64_nlist'           : macho64_nlist,
                    })

macho_overlay = {
     'macho32_segment_command' : [ None, {
        'segname' : [ None , ['String', dict(length = 16)]],
        }],

     'macho64_segment_command' : [ None, {
        'segname' : [ None , ['String', dict(length = 16)]],
        }],

     'macho32_section' : [ None, {
        'sectname' : [ None , ['String', dict(length = 16)]],
        }],

     'macho64_section' : [ None, {
        'sectname' : [ None , ['String', dict(length = 16)]],
        }],
}
 
class MachoOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'mac'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.merge_overlay(macho_overlay)


