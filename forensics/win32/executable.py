# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
@author:       Brendan Dolan-Gavitt and AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu,awalters@volatilesystems.com
@organization: Volatile Systems LLC
"""

from forensics.object import *
import struct

def round_up(addr, align):
    if addr % align == 0: return addr
    else: return (addr + (align - (addr % align)))

def round_down(addr, align):
    if addr % align == 0: return addr
    else: return (addr - (addr % align))

def write_value(of, value_type, addr, data):
    pack_str = builtin_types[value_type][1]
    packed_data = struct.pack('='+pack_str, data)
    of.seek(addr)
    of.write(packed_data)

def write_obj(of, types, field, addr, data):
    off, tp = get_obj_offset(types, field)
    write_value(of, tp, addr+off, data)

def read_section(addr_space, sect, img_base, size):
    section_start = img_base + sect['VirtualAddress']
    return addr_space.zread(section_start, sect['SizeOfRawData'])

def write_section_header(of, types, orig_header, sect, addr):
    # Write original header
    of.seek(addr)
    of.write(orig_header)

    # Change some values
    for f in sect:
        data = sect[f]
        f = f.split("_")
        write_obj(of, types, ['_IMAGE_SECTION_HEADER'] + f, addr, data)

def get_sections_start(addr_space, types, header):
    nt_header = header + read_obj(addr_space, types,
            ["_IMAGE_DOS_HEADER", "e_lfanew"], header)
    optional_header_start,_ = get_obj_offset(types,
            ['_IMAGE_NT_HEADERS', 'OptionalHeader'])
    optional_header_size = read_obj(addr_space, types,
            ['_IMAGE_NT_HEADERS', 'FileHeader', 'SizeOfOptionalHeader'],
            nt_header)
    sections_start = nt_header + optional_header_start + optional_header_size
    return sections_start - header

def section_list(addr_space, types, header):
    nt_header = header + read_obj(addr_space, types,
            ["_IMAGE_DOS_HEADER", "e_lfanew"], header)
    num_sections = read_obj(addr_space, types,
            ["_IMAGE_NT_HEADERS", "FileHeader", "NumberOfSections"],
            nt_header)
    sections_start = get_sections_start(addr_space, types, header)
    section_header_size = obj_size(types, '_IMAGE_SECTION_HEADER')
    return [ header + sections_start + (i*section_header_size)
             for i in range(num_sections) ]

def sanity_check_section(sect, image_size):
    # Note: all addresses here are RVAs
    if sect['VirtualAddress'] > image_size:
        raise ValueError('VirtualAddress %08x is past the end of image.' %
                                sect['VirtualAddress'])
    if sect['Misc_VirtualSize'] > image_size:
        raise ValueError('VirtualSize %08x is larger than image size.' %
                                sect['Misc_VirtualSize'])
    if sect['SizeOfRawData'] > image_size:
        raise ValueError('SizeOfRawData %08x is larger than image size.' %
                                sect['SizeOfRawData'])

def get_file_align(addr_space, types, addr):
    nt_header = addr + read_obj(addr_space, types,
            ["_IMAGE_DOS_HEADER", "e_lfanew"], addr)
    file_align = read_obj(addr_space, types,
            ["_IMAGE_NT_HEADERS", "OptionalHeader", "FileAlignment"],
            nt_header)
    return file_align

def get_sect_align(addr_space, types, addr):
    nt_header = addr + read_obj(addr_space, types,
            ["_IMAGE_DOS_HEADER", "e_lfanew"], addr)
    sect_align = read_obj(addr_space, types,
            ["_IMAGE_NT_HEADERS", "OptionalHeader", "SectionAlignment"],
            nt_header)
    return sect_align

def get_size_of_image(addr_space, types, addr):
    nt_header = addr + read_obj(addr_space, types,
            ["_IMAGE_DOS_HEADER", "e_lfanew"], addr)
    size = read_obj(addr_space, types,
            ["_IMAGE_NT_HEADERS", "OptionalHeader", "SizeOfImage"],
            nt_header)
    return size 

def get_size_of_headers(addr_space, types, addr):
    nt_header = addr + read_obj(addr_space, types,
            ["_IMAGE_DOS_HEADER", "e_lfanew"], addr)
    size = read_obj(addr_space, types,
            ["_IMAGE_NT_HEADERS", "OptionalHeader", "SizeOfHeaders"],
            nt_header)
    return size 

def section_entry(addr_space, types, sect_addr):
    fields = [ ['VirtualAddress'], ['Misc', 'VirtualSize'],
               ['SizeOfRawData'], ['PointerToRawData'] ]
    sect = {}

    (name_off,_) = get_obj_offset(types, ['_IMAGE_SECTION_HEADER',
        'Name'])
    name_len = 8
    sect['Name'] = addr_space.zread(sect_addr + name_off, name_len)

    for f in fields:
        val = read_obj(addr_space, types,
            ['_IMAGE_SECTION_HEADER'] + f, sect_addr)
        sect["_".join(f)] = val
    return sect

def audit_read_write(addr_space,types,data_start,data_size,ofile):
    first_block = 0x1000 - data_start % 0x1000
    full_blocks = ((data_size + (data_start % 0x1000)) / 0x1000) - 1
    left_over = (data_size + data_start) % 0x1000

    paddr = addr_space.vtop(data_start)

    # Deal with reads that are smaller than a block
    if data_size < first_block:
        data_read = addr_space.zread(data_start,data_size)
        if paddr == None:
            print "Memory Not Accessible: Virtual Address: 0x%x File Offset: 0x%x Size: 0x%x"%(data_start,ofile.tell(),data_size)
        ofile.write(data_read)
        return
            
    data_read = addr_space.zread(data_start,first_block)
    if paddr == None:
        print "Memory Not Accessible: Virtual Address: 0x%x File Offset: 0x%x Size: 0x%x"%(data_start,ofile.tell(),first_block)
    ofile.write(data_read)

    # The middle part of the read
    new_vaddr = data_start + first_block

    for i in range(0,full_blocks):
        data_read = addr_space.zread(new_vaddr, 0x1000)
        if addr_space.vtop(new_vaddr) == None:
            print "Memory Not Accessible: Virtual Address: 0x%x File Offset: 0x%x Size: 0x%x"%(new_vaddr,ofile.tell(),0x1000)
        ofile.write(data_read)    
        new_vaddr = new_vaddr + 0x1000	    

    # The last part of the read
    if left_over > 0:
        data_read = addr_space.zread(new_vaddr, left_over)
        if addr_space.vtop(new_vaddr) == None:
            print "Memory Not Accessible: Virtual Address: 0x%x File Offset: 0x%x Size: 0x%x"%(new_vaddr,ofile.tell(),left_over)       
        ofile.write(data_read)	
    return


def rebuild_exe_dsk(addr_space, types, addr, of, safe=True):
    file_align = get_file_align(addr_space, types, addr)
    header_size = get_size_of_headers(addr_space, types, addr)
    img_size = get_size_of_image(addr_space, types, addr)
    header = addr_space.zread(addr, header_size) 

    of.seek(0)
    of.write(header)
    sections = section_list(addr_space, types, addr)
    for s_addr in sections:
        sect = section_entry(addr_space, types, s_addr)
        if safe:
            sanity_check_section(sect, img_size)
        section_start = addr + sect['VirtualAddress']
        file_offset_align = round_down(sect['PointerToRawData'], file_align)
        if file_offset_align!= sect['PointerToRawData']:
            print "Warning: section start on disk not aligned to file alignment."
            print "Warning: adjusted section start from %x to %x." % (sect['PointerToRawData'],file_offset_align)
        of.seek(file_offset_align)
        audit_read_write(addr_space, types, 
            section_start,sect['SizeOfRawData'],of)

# ***********************************************************************
# * OLD -- Do not use! Has many problems:                               *
# *  1. Assumes header is no more than 0x1000 bytes                     *
# *  2. Reads section by section, so data in slack space may be missed. *
# ***********************************************************************
#def rebuild_exe_mem(addr_space, types, addr, of):
#    header = addr_space.read(addr, 0x1000) 
#
#    of.seek(0)
#    of.write(header)
#
#    file_align = get_file_align(addr_space, types, addr)
#    sections = section_list(addr_space, types, addr)
#    section_header_size = obj_size(types, '_IMAGE_SECTION_HEADER')
#    orig_sections = [section_entry(addr_space, types, s) for s in sections ]
#
#    # Write out whole image (base through base+sizeofimage)
#    # Loop over sections, set PointerToRawData = VirtualAddress and
#    #                         SizeOfRawData = max(next_section, virtual_size)
#
#    # Calculate new file positions for memory sections
#    sections_offset = min(s['PointerToRawData'] for s in orig_sections)
#    modified_sections = []
#    for i in range(len(orig_sections)):
#        new_sect = {}
#        new_sect['PointerToRawData'] = sections_offset
#
#        modified_sections.append(new_sect)
#
#        # Adjust the size of the section so it goes all
#        # the way to the beginning of the next section.
#        # If we're on the last section, make the section
#        # go until the end of the image.
#        try:
#            size = (orig_sections[i+1]['VirtualAddress'] -
#                    orig_sections[i]['VirtualAddress'])
#        except IndexError:
#            size = round_up(orig_sections[i]['Misc_VirtualSize'], file_align)
#        
#        new_sect['SizeOfRawData'] = size
#
#        sections_offset += size
#
#    # Write modified section headers
#    sections_start = get_sections_start(addr_space, types, addr)
#    for i in range(len(sections)):
#        orig_header = addr_space.read(sections[i], section_header_size)
#        write_section_header(of, types, orig_header, modified_sections[i],
#                             sections_start + (i*section_header_size))
#
#    # Write out sections to disk at the calculated positions,
#    # using their virtual size in memory
#    for orig_sect,mod_sect in zip(orig_sections, modified_sections):
#        of.seek(mod_sect['PointerToRawData'])
#        section_start = addr + orig_sect['VirtualAddress']
#        sect_data = addr_space.read(section_start, orig_sect['Misc_VirtualSize'])
#        of.write(sect_data)

def rebuild_exe_mem(addr_space, types, addr, of, safe=True):
    sect_align = get_sect_align(addr_space, types, addr)
    img_size = get_size_of_image(addr_space, types, addr)

    sections = section_list(addr_space, types, addr)
    section_header_size = obj_size(types, '_IMAGE_SECTION_HEADER')
    orig_sections = [section_entry(addr_space, types, s) for s in sections ]

    if safe:
        for sect in orig_sections:
            sanity_check_section(sect, img_size)

    of.seek(0)
    audit_read_write(addr_space, types, 
           addr,img_size,of)

    modified_sections = []
    for i in range(len(orig_sections)):
        new_sect = {}
        new_sect['PointerToRawData'] = orig_sections[i]['VirtualAddress']

        # Each section should end where the next section starts.
        # For the last section, use the in-memory size.
        try:
            size = (orig_sections[i+1]['VirtualAddress'] -
                    orig_sections[i]['VirtualAddress'])
        except IndexError:
            size = round_up(orig_sections[i]['Misc_VirtualSize'], sect_align)
        
        new_sect['SizeOfRawData'] = size
        new_sect['Misc_VirtualSize'] = size

        modified_sections.append(new_sect)

    # Write modified section headers
    sections_start = get_sections_start(addr_space, types, addr)
    for i in range(len(sections)):
        orig_header = addr_space.zread(sections[i], section_header_size)
        write_section_header(of, types, orig_header, modified_sections[i],
                             sections_start + (i*section_header_size))
