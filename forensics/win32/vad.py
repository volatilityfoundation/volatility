# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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


# The source code in this file was inspired by the excellent work of
# Brendan Dolan-Gavitt. Background information can be found in 
# the following reference:
# "The VAD Tree: A Process-Eye View of Physical Memory," Brendan Dolan-Gavitt

from forensics.win32.handles import *
from forensics.win32.info import *
from forensics.object import *
import os

vad_flags = { \
'_MMVAD_FLAGS' : { \
  'CommitCharge' : [0x0, 0x13], \
  'PhysicalMapping' : [0x13, 0x1], \
  'ImageMap' : [0x14, 0x1], \
  'UserPhysicalPages' : [0x15, 0x1], \
  'NoChange' : [0x16, 0x1], \
  'WriteWatch' : [0x17, 0x1], \
  'Protection' : [0x18, 0x5], \
  'LargePages' : [0x1D, 0x1], \
  'MemCommit' : [0x1E, 0x1], \
  'PrivateMemory' : [0x1F, 0x1], \
},
'_MMVAD_FLAGS2' : { \
  'FileOffset' : [0x0, 0x18], \
  'SecNoChange' : [0x18, 0x1], \
  'OneSecured' : [0x19, 0x1], \
  'MultipleSecured' : [0x1a, 0x1], \
  'ReadOnly' : [0x1b, 0x1], \
  'LongVad' : [0x1c, 0x1], \
  'ExtendableFile' : [0x1d, 0x1], \
  'Inherit' : [0x1e, 0x1], \
  'CopyOnWrite' : [0x1f, 0x1], \
},
'_MMSECTION_FLAGS' : { \
   'BeingDeleted' : [0x0, 0x1], \
   'BeingCreated' : [0x1, 0x1], \
   'BeingPurged'  : [0x2, 0x1], \
   'NoModifiedWriting' : [ 0x3, 0x1], \
   'FailAllIo' : [0x4, 0x1], \
   'Image' : [0x5, 0x1], \
   'Based' : [0x6, 0x1], \
   'File'  : [0x7, 0x1], \
   'Networked' : [0x8, 0x1], \
   'NoCache' : [0x9, 0x1], \
   'PhysicalMemory' : [0xa, 0x1], \
   'CopyOnWrite' : [0xb, 0x1], \
   'Reserve' : [0xc, 0x1], \
   'Commit' : [0xd, 0x1], \
   'FloppyMedia' : [0xe, 0x1], \
   'WasPurged' : [0xf, 0x1], \
   'UserReference' : [0x10, 0x1], \
   'GlobalMemory' : [0x11, 0x1], \
   'DeleteOnClose' : [0x12, 0x1], \
   'FilePointerNull' : [0x13, 0x1], \
   'DebugSymbolsLoaded' : [0x14, 0x1], \
   'SetMappedFileIoComplete' : [0x15, 0x1], \
   'CollidedFlush' : [0x16, 0x1], \
   'NoChange' : [0x17, 0x1], \
   'HadUserReference' : [0x18, 0x1], \
   'ImageMappedInSystemSpace' : [0x19, 0x1], \
   'UserWritable' : [0x1a, 0x1], \
   'Accessed' : [0x1b, 0x1], \
   'GlobalOnlyPerSession' : [0x1c, 0x1], \
   'Rom' : [0x1d, 0x1], \
   'filler' : [0x1e, 0x2], \
}
}

def get_mask_flag(flags, member):
    if not vad_flags.has_key(flags):
        raise Exception('Invalid flags ' + flags)
    flag_dict = vad_flags[flags]
    v = flag_dict[member]
    bits = 2**v[1] - 1
    mask = bits << v[0]
    return mask

def get_bit_flags(value, flags):
    matches = []
    if not vad_flags.has_key(flags):
        raise Exception('Invalid flags ' + flags)
    bit_dict = vad_flags[flags] 
    for (k,v) in bit_dict.items():
        if ((v[1] == 0x1) and ((( 1 << (v[0])) & value) > 0)):
            matches.append(k)
    return matches

def traverse_vad(parent, addr_space, types, vad_addr, prefix_callback, infix_callback, postfix_callback, level=0, storage = None):

    if not addr_space.is_valid_address(vad_addr):
        return

    Parent = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'Parent'], vad_addr)

    if not parent == None:
        if not Parent == parent:
            return 

    LeftChild = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'LeftChild'], vad_addr)

    RightChild = read_obj(addr_space, types,
                          ['_MMVAD_SHORT', 'RightChild'], vad_addr)
    
    if prefix_callback != None:
        prefix_callback(addr_space, types, vad_addr, level, storage)

    if LeftChild > 0:
        traverse_vad(vad_addr, addr_space, types, LeftChild, prefix_callback, infix_callback, postfix_callback, level+1,storage)

    if infix_callback != None:
        infix_callback(addr_space, types, vad_addr, level, storage)

    if RightChild > 0:
        traverse_vad(vad_addr, addr_space, types, RightChild, prefix_callback, infix_callback, postfix_callback, level+1,storage)

    if postfix_callback != None:
        postfix_callback(addr_space, types, vad_addr, level,storage)


def parse_vad(parent, addr_space, types, vad_addr, vadlist, level=0):

    if not addr_space.is_valid_address(vad_addr):
       return

    LeftChild = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'LeftChild'], vad_addr)

    RightChild = read_obj(addr_space, types,
                          ['_MMVAD_SHORT', 'RightChild'], vad_addr)

    vadlist.append(vad_addr)

    if LeftChild > 0:
        parse_vad(vad_addr, addr_space, types, LeftChild, vadlist, level+1)

    if RightChild > 0:
        parse_vad(vad_addr, addr_space, types, RightChild, vadlist, level+1)

def controlarea_filepointer(addr_space, types, ControlArea):
    return read_obj(addr_space, types,
                    ['_CONTROL_AREA', 'FilePointer'], ControlArea)

def print_vad_short(addr_space, types, vad_entry):

    tag_addr = vad_entry - 0x4
    if not addr_space.is_valid_address(tag_addr):
        print "Not Valid"
    tag = addr_space.read(tag_addr,4)
           
    StartingVpn = read_obj(addr_space, types,
                           ['_MMVAD_LONG', 'StartingVpn'], vad_entry)  

    StartingVpn = StartingVpn << 12

    EndingVpn = read_obj(addr_space, types,
                         ['_MMVAD_LONG', 'EndingVpn'], vad_entry)

    EndingVpn = ((EndingVpn+1) << 12) - 1

    print "VAD node @%08x Start %08x End %08x Tag %4s"%(vad_entry,StartingVpn,EndingVpn,tag)

    (u_offset, tmp) = get_obj_offset(types, ['_MMVAD_LONG', 'u'])

    Flags = read_value(addr_space, 'unsigned long', u_offset+vad_entry)
      
    flags = "Flags: " + ", ".join(get_bit_flags(Flags,'_MMVAD_FLAGS'))
    print flags

    print "Commit Charge: %d Protection: %x" % (Flags & get_mask_flag('_MMVAD_FLAGS', 'CommitCharge'),(Flags & get_mask_flag('_MMVAD_FLAGS', 'Protection')) >> 24)



def print_vad_control(addr_space, types, vad_entry):
               
    ControlArea = read_obj(addr_space, types,
                           ['_MMVAD_LONG', 'ControlArea'], vad_entry)
    ControlAreaObject = addr_space.read(ControlArea,obj_size(types,'_CONTROL_AREA'))

    if addr_space.is_valid_address(ControlArea) and ControlAreaObject != None:

        Segment = read_obj(addr_space, types,
                           ['_CONTROL_AREA', 'Segment'], ControlArea)

        print "ControlArea @%08x Segment %08x" % (ControlArea, Segment)

        Flink = read_obj(addr_space, types, ['_CONTROL_AREA', 'DereferenceList', 'Flink'],ControlArea)

        Blink = read_obj(addr_space, types, ['_CONTROL_AREA', 'DereferenceList', 'Blink'],ControlArea)

        print "Dereference list: Flink %08x, Blink %08x"%(Flink,Blink)

        NumberOfSectionReferences = read_obj(addr_space, types,
            ['_CONTROL_AREA', 'NumberOfSectionReferences'], ControlArea)

        NumberOfPfnReferences = read_obj(addr_space, types,
            ['_CONTROL_AREA', 'NumberOfPfnReferences'], ControlArea)

        print "NumberOfSectionReferences: %10d NumberOfPfnReferences:  %10d"%(NumberOfSectionReferences,NumberOfPfnReferences)

        NumberOfMappedViews = read_obj(addr_space, types,
             ['_CONTROL_AREA', 'NumberOfMappedViews'], ControlArea)

        NumberOfSubsections = read_obj(addr_space, types,
             ['_CONTROL_AREA', 'NumberOfSubsections'], ControlArea)

        print "NumberOfMappedViews:       %10d NumberOfSubsections:    %10d" % (NumberOfMappedViews,NumberOfSubsections)

        FlushInProgressCount = read_obj(addr_space, types,
             ['_CONTROL_AREA', 'FlushInProgressCount'], ControlArea)
 
        NumberOfUserReferences = read_obj(addr_space, types,
             ['_CONTROL_AREA', 'NumberOfUserReferences'], ControlArea)

        print "FlushInProgressCount:      %10d NumberOfUserReferences: %10d"%(FlushInProgressCount,NumberOfUserReferences)

        (u_offset, tmp) = get_obj_offset(types, ['_CONTROL_AREA', 'u'])
        Flags = read_value(addr_space, 'unsigned long', u_offset+ControlArea)

        flags = "Flags: " + ", ".join(get_bit_flags(Flags,'_MMSECTION_FLAGS'))
        print flags

        FilePointer = controlarea_filepointer(addr_space, types, ControlArea)
        
        if FilePointer != None and addr_space.is_valid_address(FilePointer) and FilePointer != 0x0:

            filename = file_name(addr_space, types, FilePointer)

            pFilePointer = addr_space.vtop(FilePointer)

            print "FileObject @%08x (%08x), Name: %s" % (FilePointer, pFilePointer, filename)
        else:
            print "FileObject: none"

        WaitingForDeletion = read_obj(addr_space, types,
                          ['_CONTROL_AREA', 'WaitingForDeletion'], ControlArea)

        ModifiedWriteCount = read_obj(addr_space, types,
	                  ['_CONTROL_AREA', 'ModifiedWriteCount'], ControlArea)

        NumberOfSystemCacheViews = read_obj(addr_space, types,
	         ['_CONTROL_AREA', 'NumberOfSystemCacheViews'], ControlArea)

        print "WaitingForDeletion Event: %08x"%WaitingForDeletion
        print "ModifiedWriteCount: %8d NumberOfSystemCacheViews: %8d"%(ModifiedWriteCount,NumberOfSystemCacheViews)


def print_vad_ext(addr_space, types, vad_entry):


    FirstPrototypePte = read_obj(addr_space, types,
                                ['_MMVAD_LONG', 'FirstPrototypePte'], vad_entry)
    LastContiguousPte = read_obj(addr_space, types,
                                ['_MMVAD_LONG', 'LastContiguousPte'], vad_entry)
    print "First prototype PTE: %08x Last contiguous PTE: %08x"%(FirstPrototypePte,LastContiguousPte)
 
    (u2_offset, tmp) = get_obj_offset(types, ['_MMVAD_LONG', 'u2'])

    Flags = read_value(addr_space, 'unsigned long', u2_offset+vad_entry)          
    flags = "Flags2: " + ", ".join(get_bit_flags(Flags,'_MMVAD_FLAGS2'))
    print flags

    print "File offset: %08x" % (Flags & get_mask_flag('_MMVAD_FLAGS2','FileOffset'))

    if (Flags and
        Flags & get_mask_flag('_MMVAD_FLAGS2','LongVad')):
               
        (u3_offset, tmp) = get_obj_offset(types, ['_MMVAD_LONG', 'u3'])

        StartVpn = read_value(addr_space, 'unsigned long', u3_offset+vad_entry)
        EndVpn = read_value(addr_space, 'unsigned long', u3_offset+4+vad_entry)

        (u4_offset, tmp) = get_obj_offset(types, ['_MMVAD_LONG', 'u4'])
        ExtendedInfo = read_value(addr_space, 'unsigned long', u4_offset+vad_entry)

        print "Secured: %08x - %08x" %(StartVpn,EndVpn)
        print "Pointer to _MMEXTEND_INFO (or _MMBANKED_SECTION ?): %08x"%ExtendedInfo

def append_entry(addr_space, types, vad_addr, level, storage):
    storage.append(vad_addr)

def vad_info(addr_space, types, VadRoot):

    vadlist = []
   
    traverse_vad(None, addr_space, types, VadRoot, append_entry, None, None, 0, vadlist)

    # Use the tag to determine what data type
    for vad_entry in vadlist: 
        tag_addr = vad_entry - 0x4
        if not addr_space.is_valid_address(tag_addr):
            print "Not Valid"
        tag = addr_space.read(tag_addr,4)

        # Let's classify the VADS
        if tag == "Vadl":
           
            print_vad_short(addr_space, types, vad_entry)

            ControlArea = read_obj(addr_space, types,
	                           ['_MMVAD_LONG', 'ControlArea'], vad_entry)

            if addr_space.is_valid_address(ControlArea):
                print_vad_control(addr_space, types, vad_entry)


            print_vad_ext(addr_space, types, vad_entry)

            print 

        elif tag == "VadS":

            print_vad_short(addr_space, types, vad_entry)
            print

        elif tag == "Vad ":
        
            print_vad_short(addr_space, types, vad_entry)

            ControlArea = read_obj(addr_space, types,
	                       ['_MMVAD_LONG', 'ControlArea'], vad_entry)
            if addr_space.is_valid_address(ControlArea):
                print_vad_control(addr_space, types, vad_entry) 

            print_vad_ext(addr_space,types, vad_entry)

            print 

        else:
            print "ERROR: Unknown tag"

def vad_dump(addr_space, types, VadRoot, name, offset, dir):

    vadlist = []

    if not dir == None:
        if not os.path.exists(dir):
            os.mkdir(dir)
	   
    traverse_vad(None, addr_space, types, VadRoot, append_entry, None, None, 0, vadlist)

    for vad_entry in vadlist: 
        if not addr_space.is_valid_address(vad_entry):
            continue

        range_data = ""
        StartingVpn = read_obj(addr_space, types,
                               ['_MMVAD_SHORT', 'StartingVpn'], vad_entry) 
 
        if StartingVpn == None:
            continue
 
        StartingVpn = StartingVpn << 12

        EndingVpn = read_obj(addr_space, types,
	                           ['_MMVAD_SHORT', 'EndingVpn'], vad_entry)

        if EndingVpn == None:
            continue
	
        if StartingVpn > 0xFFFFFFFF or EndingVpn > 0xFFFFFFFF:
            continue

        EndingVpn = ((EndingVpn+1) << 12) - 1
        Range = EndingVpn - StartingVpn + 1   

        NumberOfPages = Range >> 12

        for i in range(0,NumberOfPages):
            page_addr = StartingVpn+i*0x1000
            if not addr_space.is_valid_address(page_addr):
                range_data + ('\0' * 0x1000)
                continue
            page_read = addr_space.read(page_addr, 0x1000)
            if page_read == None:
                range_data = range_data + ('\0' * 0x1000)
            else:
                range_data = range_data + page_read

        if not dir == None:
            f = open(dir+"/"+"%s.%x.%08x-%08x.dmp" % (name,offset,StartingVpn,EndingVpn), 'wb')
        else:
            f = open("%s.%x.%08x-%08x.dmp" % (name,offset,StartingVpn,EndingVpn), 'wb')

        f.write(range_data)
        f.close()
 

def print_vad_table(addr_space, types, vad_addr,level, storage):
    
    tag_addr = vad_addr - 0x4
    if not addr_space.is_valid_address(tag_addr):
        return

    tag = addr_space.read(tag_addr,4)

    EndingVpn = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'EndingVpn'], vad_addr)
    EndingVpn = ((EndingVpn+1) << 12) - 1

    StartingVpn = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'StartingVpn'], vad_addr)
    StartingVpn = StartingVpn << 12

    LeftChild = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'LeftChild'], vad_addr)

    RightChild = read_obj(addr_space, types,
                             ['_MMVAD_SHORT', 'RightChild'], vad_addr)

    Parent = read_obj(addr_space, types,
                             ['_MMVAD_SHORT', 'Parent'], vad_addr)
    
    print "%08x %08x %08x %08x %08x %08x %-4s"%(vad_addr,
                                             Parent, LeftChild,        
                                             RightChild, StartingVpn,
                                             EndingVpn,tag)

def print_vad_dot_prefix(addr_space, types, vad_addr, level, storage):
    
    tag_addr = vad_addr - 0x4
    if not addr_space.is_valid_address(tag_addr):
        return

    tag = addr_space.read(tag_addr,4)

    EndingVpn = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'EndingVpn'], vad_addr)

    EndingVpn = ((EndingVpn+1) << 12) - 1

    StartingVpn = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'StartingVpn'], vad_addr)

    StartingVpn = StartingVpn << 12

    LeftChild = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'LeftChild'], vad_addr)

    RightChild = read_obj(addr_space, types,
                             ['_MMVAD_SHORT', 'RightChild'], vad_addr)

    Parent = read_obj(addr_space, types,
                             ['_MMVAD_SHORT', 'Parent'], vad_addr)
        
    print 'vad_%x [label = "{ %08x - %08x }" shape = "record" color = "blue"];'%(vad_addr, StartingVpn, EndingVpn)
    
    if LeftChild > 0:
        print "vad_%x -> vad_%x"%(vad_addr, LeftChild)


def print_vad_dot_infix(addr_space, types, vad_addr, level, storage):

    RightChild = read_obj(addr_space, types,
                             ['_MMVAD_SHORT', 'RightChild'], vad_addr)
    
    if RightChild > 0:
        print "vad_%x -> vad_%x"%(vad_addr, RightChild)


def print_vad_tree(addr_space, types, vad_addr, level, storage):
    
    EndingVpn = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'EndingVpn'], vad_addr)

    EndingVpn = ((EndingVpn+1) << 12) - 1    

    StartingVpn = read_obj(addr_space, types,
                         ['_MMVAD_SHORT', 'StartingVpn'], vad_addr)

    StartingVpn = StartingVpn << 12

    
    print " "*level +"%08x - %08x"%(StartingVpn,EndingVpn)
