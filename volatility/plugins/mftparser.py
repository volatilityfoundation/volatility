# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie@memoryanalysis.net>
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

"""
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie@memoryanalysis.net
@organization: Volatility Foundation
"""

# Information for this script taken heavily from File System Forensic Analysis by Brian Carrier
from volatility import renderers

import volatility.plugins.common as common
from volatility.renderers.basic import Address
import volatility.plugins.overlays.basic as basic
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.debug as debug
import struct
import binascii
import os
import volatility.poolscan as poolscan
import sys
reload(sys)
sys.setdefaultencoding('utf8')

class UnicodeString(basic.String):
    def __str__(self):
        result = self.obj_vm.zread(self.obj_offset, self.length).split("\x00\x00")[0].decode("utf16", "ignore")
        if not result:
            result = ""
        return result

    def v(self):
        result = self.obj_vm.zread(self.obj_offset, self.length).split("\x00\x00")[0].decode("utf16", "ignore")
        if not result:
            return obj.NoneObject("Cannot read string length {0} at {1:#x}".format(self.length, self.obj_offset))
        return result

ATTRIBUTE_TYPE_ID = {
    0x10:"STANDARD_INFORMATION",
    0x20:"ATTRIBUTE_LIST",
    0x30:"FILE_NAME",
    0x40:"OBJECT_ID",
    0x50:"SECURITY_DESCRIPTOR",
    0x60:"VOLUME_NAME",
    0x70:"VOLUME_INFORMATION",
    0x80:"DATA",
    0x90:"INDEX_ROOT",
    0xa0:"INDEX_ALLOCATION",
    0xb0:"BITMAP",
    0xc0:"REPARSE_POINT",
    0xd0:"EA_INFORMATION",  #Extended Attribute
    0xe0:"EA",
    0xf0:"PROPERTY_SET",
    0x100:"LOGGED_UTILITY_STREAM",
    #0xFFFFFFFF:"END_OF_ATTRIBUTES" # Not a real attribute, just marker found in MFT after last attribute -YK
}

VERBOSE_STANDARD_INFO_FLAGS = {
    0x1:"Read Only",
    0x2:"Hidden",
    0x4:"System",
    0x20:"Archive",
    0x40:"Device",
    0x80:"Normal",
    0x100:"Temporary",
    0x200:"Sparse File",
    0x400:"Reparse Point",
    0x800:"Compressed",
    0x1000:"Offline",
    0x2000:"Content not indexed",
    0x4000:"Encrypted",
    0x10000000:"Directory",
    0x20000000:"Index view",
}

# this method taken from mftscan by tecamac in issue 309:
# http://code.google.com/p/volatility/issues/detail?id=309
# I like that it's more readable than the long version I had above :-)
SHORT_STANDARD_INFO_FLAGS = {
    0x1:"r",
    0x2:"h",
    0x4:"s",
    0x20:"a",
    0x40:"d",
    0x80:"n",
    0x100:"t",
    0x200:"S",
    0x400:"r",
    0x800:"c",
    0x1000:"o",
    0x2000:"I",
    0x4000:"e",
    0x10000000:"D",
    0x20000000:"i",
}


FILE_NAME_NAMESPACE = {
    0x0:"POSIX", # Case sensitive, allows all Unicode chars except '/' and NULL
    0x1:"Win32", # Case insensitive, allows most Unicide except specials ('/', '\', ';', '>', '<', '?')
    0x2:"DOS",   # Case insensitive, upper case, no special chars, name is 8 or fewer chars in name and 3 or less extension
    0x3:"Win32 & DOS", # Used when original name fits in DOS namespace and 2 names are not needed
}

MFT_FLAGS = {
    0x1:"In Use",
    0x2:"Directory", # if flag & 0x0002 == 0 this is a regular file
}

INDEX_ENTRY_FLAGS = {
    0x1:"Child Node Exists",
    0x2:"Last entry in list",
}

MFT_PATHS_FULL = {}

class MFT_FILE_RECORD(obj.CType):
    def remove_unprintable(self, str):
        return str.encode("utf8", "ignore")

    def get_base_filename(self):
        if self.FileRefBaseRecord != 0: # This is a continuation of another entry
            record = MFT_PATHS_FULL.get(long(self.FileRefBaseRecord), None)
            if record != None:
                base_file = record["filename"]
                return base_file
        return None
    
    # Changed logic so it processes correct Record+Seq, this means output will reflect current status, 
    # For deleted files, this does not match but thats better than showing active files with incorrect paths.
    # Also added workaround for handling recently deleted files in get_full_path() function below. -YK
    def add_path(self, fileinfo):
        # it doesn't really make sense to add regular files to parent directory,
        # since they wouldn't actually be in the middle of a file path, but at the end
        # therefore, we'll return for regular files
        # # Removing this optimization because we need the files for continuing MFT records 
        #   which reference baseRecord. - YK
        #if not self.is_directory(): 
        #    return
        # otherwise keep a record of the directory that we've found
        ref = long(self.RecordNumber | (self.SequenceValue << 48))
        cur = MFT_PATHS_FULL.get(ref, None) # 6 bytes of record, 2 bytes of seq, makes 8 bytes of reference
        if (cur == None or fileinfo.Namespace != 2) and fileinfo.is_valid():
            temp = {}
            temp["ParentDirectory"] = long(fileinfo.ParentDirectory)
            temp["filename"] = self.remove_unprintable(fileinfo.get_name())
            MFT_PATHS_FULL[ref] = temp

    def get_full_path(self, fileinfo):
        if self.obj_vm._config.DEBUGOUT:
            print "Building path for file {0}".format(fileinfo.get_name())
        parent = ""
        path = self.remove_unprintable(fileinfo.get_name()) or "(Null)"
        try:
            parent_id = long(fileinfo.ParentDirectory) # & 0xffffffffffff # Bug fixed but not needed now
        except struct.error:
            return path
        if long(self.RecordNumber) == 5 or long(self.RecordNumber) == 0:
            return path
        seen = set()
        processing_deleted = False
        while parent != {}:
            if processing_deleted == False : seen.add(parent_id)
            parent = MFT_PATHS_FULL.get(parent_id, {})
            if parent == {} and processing_deleted == False:
                # Perhaps its parent folder is deleted and the parent folder's sequence number has advanced by one
                rec = parent_id & 0xffffffffffff
                seq = ( (parent_id >> 48) + 1 ) << 48 # incrementing seq by 1
                parent_id = rec | seq
                processing_deleted = True 
                parent = ""
                continue
            elif parent == {} or parent["filename"] == "" or parent_id & 0xffffffffffff == 0 or parent_id & 0xffffffffffff == 5:
                return path
            path = "{0}\\{1}".format(parent["filename"], path)
            parent_id = parent["ParentDirectory"] # & 0xffffffffffff # Bug fixed but not needed now
            processing_deleted = False
            if parent_id in seen:
                return path
        return path

    def is_directory(self):
        return int(self.Flags) & 0x2

    def is_file(self):
        return int(self.Flags) & 0x2 == 0

    def is_inuse(self):
        return int(self.Flags) & 0x1 == 0x1

    # Added explicit 'Deleted' notification for deleted records, previously it would just not print 'in use'.
    def get_mft_type(self):
        return "{0}{1}".format("In Use & " if self.is_inuse() else ("Deleted & " if int(self.SequenceValue) != 0 else "Unused & "),
               "Directory" if self.is_directory() else "File")

    def parse_attributes(self, mft_buff, check = True, entrysize = 1024):
        next_attr = self.ResidentAttributes
        end = mft_buff.find("\xff\xff\xff\xff")
        if end == -1:
            end = entrysize
        attributes = []
        #dataseen = False
        next_off = curr_off = self.FirstAttributeOffset
        
        # Refactored this function to change the logic a bit (using Header.Length instead of ContentSize works much better), 
        # and corrected a few things. Removed assumptions about attribute order, as there is no order. No longer stops at 
        # the first unknown (unhandled) attribute, so this will now move on the the next known one and parse it.- YK
        while next_attr != None and next_attr.obj_offset <= end and next_off < entrysize: 
            attr = next_attr
            curr_off = next_off
            try:
                attr_type = ATTRIBUTE_TYPE_ID.get(int(attr.Header.Type), None)
                next_off = attr.obj_offset + attr.Header.Length # Calculate next_off and next_attr 
                if curr_off == next_off: 
                    next_attr = None
                    continue
                next_attr = self.advance_one(next_off, mft_buff, end, None)
            except struct.error:
                next_attr = None
                continue
            if attr_type == None: #or attr_type == "END_OF_ATTRIBUTES":
                next_attr = None
            elif attr_type == "STANDARD_INFORMATION":
                if self.obj_vm._config.DEBUGOUT:
                    print "Found $SI"
                if not check or attr.STDInfo.is_valid():
                    attributes.append((attr_type, attr.STDInfo))
            elif attr_type == 'FILE_NAME':
                if self.obj_vm._config.DEBUGOUT:
                    print "Found $FN"
                self.add_path(attr.FileName)
                if not check or attr.FileName.is_valid():
                    attributes.append((attr_type, attr.FileName))
            elif attr_type == "OBJECT_ID":
                if self.obj_vm._config.DEBUGOUT:
                    print "Found $ObjectId"
                if attr.Header.NonResidentFlag == 1:
                    attributes.append((attr_type, "Non-Resident OBJECT_ID"))
                    #next_attr = None # There are valid attributes after this too!
                    #continue
                else:
                    attributes.append((attr_type, attr.ObjectID))
            elif attr_type == "DATA":
                if self.obj_vm._config.DEBUGOUT:
                    print "Found $DATA"
                try:
                    if attr.Header and attr.Header.NameOffset > 0 and attr.Header.NameLength > 0:
                        adsname = ""
                        if attr != None and attr.Header != None and attr.Header.NameOffset and attr.Header.NameLength:
                            nameloc = attr.obj_offset + attr.Header.NameOffset
                            adsname = obj.Object("UnicodeString", vm = self.obj_vm, offset = nameloc, length = attr.Header.NameLength * 2)
                            if adsname != None and adsname.strip() != "": # and dataseen:
                                attr_type += " ADS Name: {0}".format(adsname.strip())
                    #dataseen = True
                except struct.error:
                    next_attr = None
                    continue
                data = DATA(0)

                start = 0
                theend = 0
                if attr.Header.NonResidentFlag == 1: # NON_RESIDENT_ATTRIBUTE
                    data.non_resident = 1
                    non_resident_attr = obj.Object('NON_RESIDENT_ATTRIBUTE', vm = self.obj_vm, offset = curr_off)
                    data.allocatedSize = non_resident_attr.AllocatedAttributeSize
                    data.logicalSize = non_resident_attr.ActualAttributeSize
                    data.initializedSize = non_resident_attr.InitializedAttributeSize
                else:
                    try:
                        if attr.ContentSize == 0:
                            attributes.append((attr_type, data))
                            continue
                    except struct.error:
                        next_attr = None
                        continue
                    data.logicalSize = attr.ContentSize
                    start = attr.obj_offset + attr.ContentOffset
                    theend = min(start + attr.ContentSize, end)
                    try:
                        contents = mft_buff[start:theend]
                    except TypeError:
                        next_attr = None
                        continue
                    data.data = contents
                attributes.append((attr_type, data))

            elif attr_type == "ATTRIBUTE_LIST":
                if self.obj_vm._config.DEBUGOUT:
                    print "Found $AttributeList"
                if attr.Header.NonResidentFlag == 1:
                    attributes.append((attr_type, "Non-Resident ATTRIBUTE_LIST"))
                else:
                    attr.process_attr_list(self.obj_vm, self, attributes, check)

        return attributes

    # No longer needs to guess position, its accurate now because we use exact size
    def advance_one(self, next_off, mft_buff, end, retval_for_end=None):
        item = None

        if next_off == None:
            return None

        try:
            val = struct.unpack("<I", mft_buff[next_off : next_off + 4])[0]
            if val == 0xFFFFFFFF:
                if retval_for_end != None:
                    item = retval_for_end
            elif None == ATTRIBUTE_TYPE_ID.get(val, None): # Check for invalid attribute types
                pass
            else:
                item = obj.Object('RESIDENT_ATTRIBUTE', vm = self.obj_vm, offset = next_off)
        except struct.error:
            return None

        return item

class RESIDENT_ATTRIBUTE(obj.CType):
    def process_attr_list(self, bufferas, mft_entry, attributes = [], check = True):
        start = 0
        end = self.ContentSize #self.obj_offset + self.ContentSize # BUG FIXED !
        while start < end:
            item = obj.Object("ATTRIBUTE_LIST", vm = bufferas,
                                offset = self.AttributeList.obj_offset + start)
            if item == None:
                return
            try:
                thetype = ATTRIBUTE_TYPE_ID.get(int(item.Type), None)
                if thetype == None:
                    return
                # -- The below commented code seems to be a misunderstanding of how ATTRIBUTE_LISTs work, they 
                #    only tell you where your attribute is located via FileReferenceLocation. The actual
                #    attributes are never stored here --- YK
                # elif item.Length > 0x20 and thetype in ["STANDARD_INFORMATION", "FILE_NAME"]:
                #     theitem = obj.Object(thetype, vm = bufferas, offset = item.AttributeID.obj_offset)
                #     if thetype == "STANDARD_INFORMATION" and (not check or theitem.is_valid()):
                #         attributes.append(("STANDARD_INFORMATION (AL)", theitem))
                #     elif thetype == "FILE_NAME" and (not check or theitem.is_valid()):
                #         mft_entry.add_path(theitem)
                #         attributes.append(("FILE_NAME (AL)", theitem))
                else:
                    if item.NameLength > 0:
                        attributes.append(("ATTRIBUTE_LIST", thetype + " " + item.Name))
                    else:
                        attributes.append(("ATTRIBUTE_LIST", thetype))

            except struct.error:
                return
            if item.Length <= 0:
                return
            start += item.Length

class STANDARD_INFORMATION(obj.CType):
    # XXX need a better check than this
    # we return valid if we have _any_ timestamp other than Null
    def is_valid(self):
        try:
            modified = self.ModifiedTime.v()
        except struct.error:
            modified = 0 
        try:
            mftaltered = self.MFTAlteredTime.v()
        except struct.error:
            mftaltered = 0 
        try:
            creation = self.CreationTime.v()
        except struct.error:
            creation = 0 
        try:
            accessed = self.FileAccessedTime.v()
        except struct.error:
            accessed = 0
        return obj.CType.is_valid(self) and (modified != 0 or mftaltered != 0 or \
                accessed != 0 or creation != 0)

    def get_type_short(self):
        try:
            if self.Flags == None:
                return "?"
        except struct.error:
            return "?"
        type = ""
        for i, j in sorted(SHORT_STANDARD_INFO_FLAGS.items()):
            if i & self.Flags == i:
                type += j
            else:
                type += "-"
        return type


    def get_type(self):
        try:
            if self.Flags == None or int(self.Flags) == 0: # Sometimes there are no flags! -YK
                return ""
        except struct.error:
            return "Unknown Type"

        type = None
        for i in VERBOSE_STANDARD_INFO_FLAGS:
            if (i & self.Flags) == i:
                if type == None:
                    type = VERBOSE_STANDARD_INFO_FLAGS[i]
                else:
                    type += " & " + VERBOSE_STANDARD_INFO_FLAGS[i]
        if type == None:
            type = "Unknown Type "
        return type

    def get_header(self):
        return [("Creation", "30"),
                ("Modified", "30"),
                ("MFT Altered", "30"),
                ("Access Date", "30"),
                ("Type", ""),
               ]

    def __str__(self):
        bufferas = addrspace.BufferAddressSpace(self.obj_vm._config, data = "\x00\x00\x00\x00\x00\x00\x00\x00")
        nulltime = obj.Object("WinTimeStamp", vm = bufferas, offset = 0, is_utc = True)
        try:
            modified = str(self.ModifiedTime)
        except struct.error:
            modified = nulltime
        try:
            mftaltered = str(self.MFTAlteredTime)
        except struct.error:
            mftaltered = nulltime
        try:
            creation = str(self.CreationTime)
        except struct.error:
            creation = nulltime
        try:
            accessed = str(self.FileAccessedTime)
        except struct.error:
            accessed = nulltime

        return "{0:20} {1:30} {2:30} {3:30} {4}".format(creation, modified, mftaltered, accessed, self.get_type())

    def body(self, path, record_num, size, offset):
        if path.strip() == "" or path == None:
            # if the path is null we just try to get the filename
            # from our dictionary and print the body file output
            record = MFT_PATHS_FULL.get(int(record_num), {})
            path = "(Possible non-base entry, extra $SI or invalid $FN)"
            if record != {}:
                # we include with the found filename a note that this may be a
                # non-base entry.  the analyst can investigate these types of records
                # on his/her own by comparing record numbers in output or examining the
                # given physical offset in memory for example
                path = "{0} {1}".format(record["filename"], path)

        try:
            modified = self.ModifiedTime.v()
        except struct.error:
            modified = 0
        try:
            mftaltered = self.MFTAlteredTime.v()
        except struct.error:
            mftaltered = 0
        try:
            creation = self.CreationTime.v()
        except struct.error:
            creation = 0
        try:
            accessed = self.FileAccessedTime.v()
        except struct.error:
            accessed = 0

        return "[{9}MFT STD_INFO] {0} (Offset: 0x{1:x})|{2}|{3}|0|0|{4}|{5}|{6}|{7}|{8}".format(
            path,
            offset,
            record_num,
            self.get_type_short(),
            size,
            accessed,
            modified,
            mftaltered,
            creation,
            self.obj_vm._config.MACHINE)

class FILE_NAME(STANDARD_INFORMATION):
    
    def remove_unprintable(self, str):
        return str.encode("utf8", "ignore")

    # XXX need a better check than this
    # we return valid if we have _any_ timestamp other than Null
    # filename must also be a non-empty string
    def is_valid(self):
        try:
            modified = self.ModifiedTime.v()
        except struct.error:
            modified = 0
        try:
            mftaltered = self.MFTAlteredTime.v()
        except struct.error:
            mftaltered = 0
        try:
            creation = self.CreationTime.v()
        except struct.error:
            creation = 0
        try:
            accessed = self.FileAccessedTime.v()
        except struct.error:
            accessed = 0
        return obj.CType.is_valid(self) and (modified != 0 or mftaltered != 0 or \
                accessed != 0 or creation != 0) #and \
                #self.remove_unprintable(self.get_name()) != ""

    def get_name(self):
        if self.NameLength == None or self.NameLength == 0:
            return ""
        return self.remove_unprintable(self.Name)

    def get_header(self):
        return [("Creation", "30"),
                ("Modified", "30"),
                ("MFT Altered", "30"),
                ("Access Date", "30"),
                ("Name/Path", ""),
               ]

    def __str__(self):
        bufferas = addrspace.BufferAddressSpace(self.obj_vm._config, data = "\x00\x00\x00\x00\x00\x00\x00\x00")
        nulltime = obj.Object("WinTimeStamp", vm = bufferas, offset = 0, is_utc = True)
        try:
            modified = str(self.ModifiedTime)
        except struct.error:
            modified = nulltime
        try:
            mftaltered = str(self.MFTAlteredTime)
        except struct.error:
            mftaltered = nulltime
        try:
            creation = str(self.CreationTime)
        except struct.error:
            creation = nulltime
        try:
            accessed = str(self.FileAccessedTime)
        except struct.error:
            accessed = nulltime

        return "{0:20} {1:30} {2:30} {3:30} {4}".format(creation, modified, mftaltered, accessed,
            self.remove_unprintable(self.get_name()))

    def get_full(self, full):
        bufferas = addrspace.BufferAddressSpace(self.obj_vm._config, data = "\x00\x00\x00\x00\x00\x00\x00\x00")
        nulltime = obj.Object("WinTimeStamp", vm = bufferas, offset = 0, is_utc = True)
        try:
            modified = str(self.ModifiedTime)
        except struct.error:
            modified = nulltime
        try:
            mftaltered = str(self.MFTAlteredTime)
        except struct.error:
            mftaltered = nulltime
        try:
            creation = str(self.CreationTime)
        except struct.error:
            creation = nulltime
        try:
            accessed = str(self.FileAccessedTime)
        except struct.error:
            accessed = nulltime
        try:
            return "{0:20} {1:30} {2:30} {3:30} {4}".format(creation,
                modified,
                mftaltered,
                accessed,
                self.remove_unprintable(full))
        except struct.error:
            return None

    def body(self, path, record_num, size, offset):
        try:
            modified = self.ModifiedTime.v()
        except struct.error:
            modified = 0
        try:
            mftaltered = self.MFTAlteredTime.v()
        except struct.error:
            mftaltered = 0
        try:
            creation = self.CreationTime.v()
        except struct.error:
            creation = 0
        try:
            accessed = self.FileAccessedTime.v()
        except struct.error:
            accessed = 0
        return "[{9}MFT FILE_NAME] {0} (Offset: 0x{1:x})|{2}|{3}|0|0|{4}|{5}|{6}|{7}|{8}".format(
            path,
            offset,
            record_num,
            self.get_type_short(),
            size,
            accessed,
            modified,
            mftaltered,
            creation,
            self.obj_vm._config.MACHINE)


# Added new class to store and print values of non-resident $DATA attributes
# File size is also available in $FN but it is not accurate as changes to file
# size are not updated in $FN. This is accurate for file size.
class DATA(object):
    def __str__(self):
        string = "DATA is " 
        if self.non_resident == 1: 
            string += "non-resident\n"
            string += "Logical     Size : " + str(self.logicalSize) + "\n"
            string += "Allocated   Size : " + str(self.allocatedSize) + "\n"
            string += "Initialized Size : " + str(self.initializedSize) + "\n"
        else:
            string += "resident\n"
            string += "Logical     Size : " + str(self.logicalSize) + "\n"
        return string
        
    def __init__(self, non_resident = 0):
        self.non_resident = non_resident # Non-Resident flag, 1=non-resident
        self.allocatedSize = 0
        self.initializedSize = 0
        self.logicalSize = 0
        self.data = "" # buffer stores resident data
        self.name = "" # stream name, default data stream has no name, this is for ADS

class OBJECT_ID(obj.CType):
    # Modified from analyzeMFT.py:
    def FmtObjectID(self, item):
        record = ""
        for i in item:
            record += str(i)
        return "{0}-{1}-{2}-{3}-{4}".format(binascii.hexlify(record[0:4]), binascii.hexlify(record[4:6]),
            binascii.hexlify(record[6:8]), binascii.hexlify(record[8:10]), binascii.hexlify(record[10:16]))

    def __str__(self):
        string = "Object ID: {0}\n".format(self.FmtObjectID(self.ObjectID))
        string += "Birth Volume ID: {0}\n".format(self.FmtObjectID(self.BirthVolumeID))
        string += "Birth Object ID: {0}\n".format(self.FmtObjectID(self.BirthObjectID))
        string += "Birth Domain ID: {0}\n".format(self.FmtObjectID(self.BirthDomainID))
        return string

# Using structures defined in File System Forensic Analysis pg 353+
MFT_types = {
    'MFT_FILE_RECORD': [ 0x400, {
        'Signature': [ 0x0, ['unsigned int']],
        'FixupArrayOffset': [ 0x4, ['unsigned short']],
        'NumFixupEntries': [ 0x6, ['unsigned short']],
        'LSN': [ 0x8, ['unsigned long long']],
        'SequenceValue': [ 0x10, ['unsigned short']],
        'LinkCount': [ 0x12, ['unsigned short']],
        'FirstAttributeOffset': [0x14, ['unsigned short']],
        'Flags': [0x16, ['unsigned short']],
        'EntryUsedSize': [0x18, ['int']],
        'EntryAllocatedSize': [0x1c, ['unsigned int']],
        'FileRefBaseRecord': [0x20, ['unsigned long long']],
        'NextAttributeID': [0x28, ['unsigned short']],
        'RecordNumber': [0x2c, ['unsigned long']],
        'FixupArray': lambda x: obj.Object("Array", offset = x.obj_offset + x.FixupArrayOffset, count = x.NumFixupEntries, vm = x.obj_vm,
                                        target = obj.Curry(obj.Object, "unsigned short")),
        'ResidentAttributes': lambda x : obj.Object("RESIDENT_ATTRIBUTE", offset = x.obj_offset + x.FirstAttributeOffset, vm = x.obj_vm),
        'NonResidentAttributes': lambda x : obj.Object("NON_RESIDENT_ATTRIBUTE", offset = x.obj_offset + x.FirstAttributeOffset, vm = x.obj_vm),
     }],

    'ATTRIBUTE_HEADER': [ 0x10, {
        'Type': [0x0, ['int']],
        'Length': [0x4, ['int']],
        'NonResidentFlag': [0x8, ['unsigned char']],
        'NameLength': [0x9, ['unsigned char']],
        'NameOffset': [0xa, ['unsigned short']],
        'Flags': [0xc, ['unsigned short']],
        'AttributeID': [0xe, ['unsigned short']],
    }],

    'RESIDENT_ATTRIBUTE': [0x16, {
        'Header': [0x0, ['ATTRIBUTE_HEADER']],
        'ContentSize': [0x10, ['unsigned int']], #relative to the beginning of the attribute
        'ContentOffset': [0x14, ['unsigned short']],
        #'IndexedFlag': [0x16, ['unsigned short']],
        'STDInfo': lambda x : obj.Object("STANDARD_INFORMATION", offset = x.obj_offset + x.ContentOffset, vm = x.obj_vm),
        'FileName': lambda x : obj.Object("FILE_NAME", offset = x.obj_offset + x.ContentOffset, vm = x.obj_vm),
        'ObjectID': lambda x : obj.Object("OBJECT_ID", offset = x.obj_offset + x.ContentOffset, vm = x.obj_vm),
        'AttributeList':lambda x : obj.Object("ATTRIBUTE_LIST", offset = x.obj_offset + x.ContentOffset, vm = x.obj_vm),
    }],

    'NON_RESIDENT_ATTRIBUTE': [0x40, {
        'Header': [0x0, ['ATTRIBUTE_HEADER']],
        'StartingVCN': [0x10, ['unsigned long long']],
        'EndingVCN': [0x18, ['unsigned long long']],
        'RunListOffset': [0x20, ['unsigned short']],
        'CompressionUnitSize': [0x22, ['unsigned short']],
        'Unused': [0x24, ['int']],
        'AllocatedAttributeSize': [0x28, ['unsigned long long']],
        'ActualAttributeSize': [0x30, ['unsigned long long']],
        'InitializedAttributeSize': [0x38, ['unsigned long long']],
    }],

    'EA_INFORMATION': [None, {
        'EaPackedLength': [0x0, ['int']],
        'EaCount': [0x4, ['int']],
        'EaUnpackedLength': [0x8, ['long']],
    }],

    'EA': [None, {
        'NextEntryOffset': [0x0, ['unsigned long long']],
        'Flags': [0x8, ['unsigned char']],
        'EaNameLength': [0x9, ['unsigned char']],
        'EaValueLength': [0xa, ['unsigned short']],
        'EaName': [0xc, ['String', dict(length = lambda x: x.EaNameLength)]],
        'EaValue': lambda x: obj.Object("Array", offset = x.obj_offset + len(x.EaName), count = x.EaValueLength, vm = x.obj_vm,
                                        target = obj.Curry(obj.Object, "unsigned char")),
    }],

    'STANDARD_INFORMATION': [0x48, {
        'CreationTime': [0x0, ['WinTimeStamp', dict(is_utc = True)]],
        'ModifiedTime': [0x8, ['WinTimeStamp', dict(is_utc = True)]],
        'MFTAlteredTime': [0x10, ['WinTimeStamp', dict(is_utc = True)]],
        'FileAccessedTime': [0x18, ['WinTimeStamp', dict(is_utc = True)]],
        'Flags': [0x20, ['int']],
        'MaxVersionNumber': [0x24, ['unsigned int']],
        'VersionNumber': [0x28, ['unsigned int']],
        'ClassID': [0x2c, ['unsigned int']],
        'OwnerID': [0x30, ['unsigned int']],
        'SecurityID': [0x34, ['unsigned int']],
        'QuotaCharged': [0x38, ['unsigned long long']],
        'USN': [0x40, ['unsigned long long']],
        'NextAttribute': [0x48, ['RESIDENT_ATTRIBUTE']],
    }],

    'FILE_NAME': [None, {
        'ParentDirectory': [0x0, ['unsigned long long']],
        'CreationTime': [0x8, ['WinTimeStamp', dict(is_utc = True)]],
        'ModifiedTime': [0x10, ['WinTimeStamp', dict(is_utc = True)]],
        'MFTAlteredTime': [0x18, ['WinTimeStamp', dict(is_utc = True)]],
        'FileAccessedTime': [0x20, ['WinTimeStamp', dict(is_utc = True)]],
        'AllocatedFileSize': [0x28, ['unsigned long long']],
        'RealFileSize': [0x30, ['unsigned long long']],
        'Flags': [0x38, ['unsigned int']],
        'ReparseValue': [0x3c, ['unsigned int']],
        'NameLength': [0x40, ['unsigned char']],
        'Namespace': [0x41, ['unsigned char']],
        'Name': [0x42, ['UnicodeString', dict(length = lambda x: x.NameLength * 2)]],
    }],

    'ATTRIBUTE_LIST': [0x20, { # 0x20 is min. length observed - YK
        'Type': [0x0, ['unsigned int']],
        'Length': [0x4, ['unsigned short']],
        'NameLength': [0x6, ['unsigned char']],
        'NameOffset': [0x7, ['unsigned char']],
        'StartingVCN': [0x8, ['unigned long long']],
        'FileReferenceLocation': [0x10, ['unsigned long long']],
        'AttributeID': [0x18, ['unsigned short']],
        'Name': [0x1A, ['UnicodeString', dict(length = lambda x: x.NameLength * 2)]]
    }],

    'OBJECT_ID': [0x40, { # This is mostly just 0x10 in size, only the objectID is present, not the other fields
        'ObjectID': [0x0, ['array', 0x10, ['char']]],
        'BirthVolumeID': [0x10, ['array', 0x10, ['char']]],
        'BirthObjectID': [0x20, ['array', 0x10, ['char']]],
        'BirthDomainID': [0x30, ['array', 0x10, ['char']]],
    }],
    
    'REPARSE_POINT': [0x10, {
        'TypeFlags': [0x0, ['unsigned int']],
        'DataSize': [0x4, ['unsigned short']],
        'Unused': [0x6, ['unsigned short']],
        'NameOffset': [0x8, ['unsigned short']],
        'NameLength': [0xa, ['unsigned short']],
        'PrintNameOffset': [0xc, ['unsigned short']],
        'PrintNameLength': [0xe, ['unsigned short']],
    }],

    'INDEX_ROOT': [None, {
        'Type': [0x0, ['unsigned int']],
        'SortingRule': [0x4, ['unsigned int']],
        'IndexSizeBytes': [0x8, ['unsigned int']],
        'IndexSizeClusters': [0xc, ['unsigned char']],
        'Unused': [0xd, ['array', 0x3, ['unsigned char']]],
        'NodeHeader': [0x10, ['NODE_HEADER']],
    }],

    'INDEX_ALLOCATION': [None, {
        'Signature': [0x0, ['unsigned int']],  #INDX though not essential
        'FixupArrayOffset': [0x4, ['unsigned short']],
        'NumFixupEntries': [ 0x6, ['unsigned short']],
        'LSN': [ 0x8, ['unsigned long long']],
        'VCN': [0x10, ['unsigned long long']],
        'NodeHeader': [0x18, ['NODE_HEADER']],
    }],

    'NODE_HEADER': [0x10, {
        'IndexEntryListOffset': [0x0, ['unsigned int']],
        'EndUsedIndexOffset': [0x4, ['unsigned int']],
        'EndAllocatedIndexOffset': [0x8, ['unsigned int']],
        'Flags': [0xc, ['unsigned int']],
    }],

    # Index entries
    'GENERIC_INDEX_ENTRY': [None, {
        'Undefined': [0x0, ['unsigned long long']],
        'EntryLength': [0x8, ['unsigned short']],
        'ContentLength': [0xa, ['unsigned short']],
        'Flags': [0xc, ['unsigned int']],
        'Content': [0x10, ['array', lambda x : x.ContentLength , ['unsigned char']]],
        # last 8 bytes are VCN of child node, which is only here if flag is set... not sure how to code that yet
    }],

    'DIRECTORY_INDEX_ENTRY': [None, {
        'MFTFileReference': [0x0, ['unsigned long long']],
        'EntryLength': [0x8, ['unsigned short']],
        'FileNameAttrLength': [0xa, ['unsigned short']],
        'Flags': [0xc, ['unsigned int']],
        'FileNameAttr': [0x16, ['FILE_NAME']],
        # last 8 bytes are VCN of child node, which is only here if flag is set... not sure how to code that yet
    }],

}

class MFTTYPES(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        profile.object_classes.update({
            'UnicodeString':UnicodeString,
            'MFT_FILE_RECORD':MFT_FILE_RECORD,
            'FILE_NAME':FILE_NAME,
            'STANDARD_INFORMATION':STANDARD_INFORMATION,
            'OBJECT_ID':OBJECT_ID,
            'RESIDENT_ATTRIBUTE':RESIDENT_ATTRIBUTE,
        })
        profile.vtypes.update(MFT_types)


class MFTScanner(scan.BaseScanner):
    checks = [ ]

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset


class MFTParser(common.AbstractWindowsCommand):
    """ Scans for and parses potential MFT entries """
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("OFFSET", short_option = "o", default = None,
                          help = "Physical offset for MFT Entries (comma delimited)")
        config.add_option('NOCHECK', short_option = 'N', default = False,
                          help = 'Only all entries including w/null timestamps',
                          action = "store_true")
        config.add_option("ENTRYSIZE", short_option = "E", default = 1024,
                          help = "MFT Entry Size",
                          action = "store", type = "int")
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                      cache_invalidator = False,
                      help = 'Directory in which to dump extracted resident files')
        config.add_option("MACHINE", default = "",
                        help = "Machine name to add to timeline header")
        config.add_option("DEBUGOUT", default = False,
                        help = "Output debugging messages",
                        action = "store_true")

    def calculate(self):
        if self._config.MACHINE != "":
            self._config.update("MACHINE", "{0} ".format(self._config.MACHINE))
        offsets = []
        address_space = utils.load_as(self._config, astype = 'physical')
        if self._config.OFFSET != None:
            items = [int(o, 16) for o in self._config.OFFSET.split(',')]
            for offset in items:
                mft_buff = address_space.read(offset, self._config.ENTRYSIZE)
                bufferas = addrspace.BufferAddressSpace(self._config, data = mft_buff)
                mft_entry = obj.Object('MFT_FILE_RECORD', vm = bufferas, offset = 0)
                offsets.append((offset, mft_entry, mft_buff))
        else:
            scanner = poolscan.MultiPoolScanner(needles = ['FILE', 'BAAD'])
            print "Scanning for MFT entries and building directory, this can take a while"
            seen = []
            for _, offset in scanner.scan(address_space):
                mft_buff = address_space.read(offset, self._config.ENTRYSIZE)
                bufferas = addrspace.BufferAddressSpace(self._config, data = mft_buff)
                name = ""
                try:
                    mft_entry = obj.Object('MFT_FILE_RECORD', vm = bufferas,
                               offset = 0)

                    temp = mft_entry.advance_one(mft_entry.ResidentAttributes.obj_offset + mft_entry.ResidentAttributes.Header.Length, mft_buff, self._config.ENTRYSIZE, "END_OF_ATTRIBUTES") 
                    if temp == None:  # Probably a bad MFT entry or false positive
                        continue
                    elif temp == "END_OF_ATTRIBUTES": # There was only a single attribute!
                        pass
                    else:
                        mft_entry.add_path(temp.FileName) # This is a hack assuming FN is the 2nd attribute, not always the case!
                        name = temp.FileName.get_name()
                except struct.error:
                    if self._config.DEBUGOUT:
                        print "Problem entry at offset:", hex(offset)
                    continue
    
                if (int(mft_entry.RecordNumber), name) in seen:
                    continue
                else:
                    seen.append((int(mft_entry.RecordNumber), name))
                offsets.append((offset, mft_entry, mft_buff))

        for offset, mft_entry, mft_buff in offsets:
            if self._config.DEBUGOUT:
                print "Processing MFT Entry at offset:", hex(offset)
            attributes = mft_entry.parse_attributes(mft_buff, not self._config.NOCHECK, self._config.ENTRYSIZE)
            yield offset, mft_entry, attributes

    def render_body(self, outfd, data):
        if self._config.DUMP_DIR != None and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")
        # Some notes: every base MFT entry should have one $SI and at lease one $FN
        # --> YK - Sometimes there is only $DATA, this happens when the data runs for a file exceed space available in that file's mft record, a new mft record is used then holding just $DATA
        # Usually $SI occurs before $FN
        # We'll make an effort to get the filename from $FN for $SI
        # If there is only one $SI with no $FN we dump whatever information it has
        for offset, mft_entry, attributes in data:
            si = None
            full = ""
            datanum = 0
            for a, i in attributes:
                # we'll have a default file size of -1 for records missing $FN attributes
                # note that file size found in $FN may not actually be accurate and will most likely
                # be 0.  See Carrier, pg 363
                size = -1
                if a.startswith("STANDARD_INFORMATION"):
                    if full != "":
                        # if we are here, we've hit one $FN attribute for this entry already and have the full name
                        # so we can dump this $SI
                        outfd.write("0|{0}\n".format(i.body(full, mft_entry.RecordNumber, size, offset)))
                    elif si != None:
                        # if we are here then we have more than one $SI attribute for this entry
                        # since we don't want to lose its info, we'll just dump it for now
                        # we won't have full path, but we'll have a filename most likely
                        outfd.write("0|{0}\n".format(i.body("", mft_entry.RecordNumber, size, offset)))
                    elif si == None:
                        # this is the usual case and we'll save the $SI to process after we get the full path from the $FN
                        si = i
                elif a.startswith("FILE_NAME"):
                    if hasattr(i, "ParentDirectory"):
                        full = mft_entry.get_full_path(i)
                        size = int(i.RealFileSize)
                        outfd.write("0|{0}\n".format(i.body(full, mft_entry.RecordNumber, size, offset)))
                        if si != None:
                            outfd.write("0|{0}\n".format(si.body(full, mft_entry.RecordNumber, size, offset)))
                            si = None
                elif a.startswith("DATA"):
                    i = i.data
                    if len(str(i)) > 0:
                        file_string = ".".join(["file", "0x{0:X}".format(offset), "data{0}".format(datanum), "dmp"])
                        datanum += 1
                        if self._config.DUMP_DIR != None:
                            of_path = os.path.join(self._config.DUMP_DIR, file_string)
                            of = open(of_path, 'wb')
                            of.write(i)
                            of.close()

            if si != None:
                # here we have a lone $SI in an MFT entry with no valid $FN.  This is most likely a non-base entry
                outfd.write("0|{0}\n".format(si.body("", mft_entry.RecordNumber, -1, offset)))

    def unified_output(self, data):
        return renderers.TreeGrid([("MFT Offset", Address),
                            ("Attribute", str),
                            ("Record", int),
                            ("Link count", int),
                            ("Type", str),
                            ("Creation", str),
                            ("Modified", str),
                            ("MFT Altered", str),
                            ("Access Date", str),
                            ("Value", str)], self.generator(data))

    def generator(self, data):
        bufferas = addrspace.BufferAddressSpace(self._config, data = "\x00\x00\x00\x00\x00\x00\x00\x00")
        nulltime = obj.Object("WinTimeStamp", vm = bufferas, offset = 0, is_utc = True)
        for offset, mft_entry, attributes in data:
            if not len(attributes):
                continue
            datnum = 0
            for a, i in attributes:
                if i == None:
                    attrdata = ["Invalid (" + a + ")", "", "", "", "", ""]
                elif a.startswith("STANDARD_INFORMATION"):
                    try:
                        modified = str(i.ModifiedTime)
                    except struct.error:
                        modified = nulltime
                    try:
                        mftaltered = str(i.MFTAlteredTime)
                    except struct.error:
                        mftaltered = nulltime
                    try:
                        creation = str(i.CreationTime)
                    except struct.error:
                        creation = nulltime
                    try:
                        accessed = str(i.FileAccessedTime)
                    except struct.error:
                        accessed = nulltime
                    attrdata = [a, creation,
                                modified,
                                mftaltered,
                                accessed,
                                i.get_type()]
                elif a.startswith("FILE_NAME"):
                    try:
                        modified = str(i.ModifiedTime)
                    except struct.error:
                        modified = nulltime
                    try:
                        mftaltered = str(i.MFTAlteredTime)
                    except struct.error:
                        mftaltered = nulltime
                    try:
                        creation = str(i.CreationTime)
                    except struct.error:
                        creation = nulltime
                    try:
                        accessed = str(i.FileAccessedTime)
                    except struct.error:
                        accessed = nulltime
                    attrdata = [a, creation,
                                modified,
                                mftaltered,
                                accessed,
                                i.remove_unprintable(i.get_name())]
                else:
                    attrdata = [a, "", "", "", "", ""]

                yield (0, [Address(offset),
                           str(mft_entry.get_mft_type()),
                           int(mft_entry.RecordNumber),
                           int(mft_entry.LinkCount)] + attrdata)


    def render_text(self, outfd, data):
        if self._config.DUMP_DIR != None and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")
        border = "*" * 75
        for offset, mft_entry, attributes in data:
            if len(attributes) == 0:
                continue
            outfd.write("{0}\n".format(border))
            outfd.write("MFT entry found at offset 0x{0:X}\n".format(offset))
            outfd.write("Attribute: {0}\n".format(mft_entry.get_mft_type()))
            outfd.write("Record Number: 0x{0:X}\n".format(mft_entry.RecordNumber)) # changed to hex
            outfd.write("Link count: {0}\n".format(mft_entry.LinkCount))
            outfd.write("\n")
            # there can be more than one resident $DATA attribute
            # e.g. ADS.  Therfore we need to differentiate somehow
            # to avoid clobbering.  For now we'll use a counter (datanum)
            datanum = 0
            for a, i in attributes:
                if i == None:
                    outfd.write("${0}: malformed entry\n".format(a))
                    continue
                if a.startswith("STANDARD_INFORMATION"):
                    outfd.write("\n${0}\n".format(a))
                    self.table_header(outfd, i.get_header())
                    outfd.write("{0}\n".format(str(i)))
                elif a.startswith("FILE_NAME"):
                    outfd.write("\n${0}\n".format(a))
                    if hasattr(i, "ParentDirectory"):
                        full = mft_entry.get_full_path(i)
                        self.table_header(outfd, i.get_header())
                        output = i.get_full(full)
                        if output == None:
                            continue
                        outfd.write("{0}\n".format(output))
                    else:
                        outfd.write("{0}\n".format(str(i)))
                elif a.startswith("DATA"):
                    outfd.write("\n${0}".format(a))
                    if mft_entry.FileRefBaseRecord != 0:
                        base_file = mft_entry.get_base_filename()
                        outfd.write(" (Base Record: 0x{0:X}".format(mft_entry.FileRefBaseRecord) + "" if base_file == None else " Base Filename: {0})".format(base_file))
                    outfd.write("\n")
                    outfd.write(str(i))
                    i = i.data
                    contents = "\n".join(["{0:010x}: {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(i)])
                    outfd.write("{0}\n".format(str(contents)))
                    if len(str(i)) > 0:
                        file_string = ".".join(["file", "0x{0:X}".format(offset), "data{0}".format(datanum), "dmp"])
                        datanum += 1
                        if self._config.DUMP_DIR != None:
                            of_path = os.path.join(self._config.DUMP_DIR, file_string)
                            of = open(of_path, 'wb')
                            of.write(i)
                            of.close()
                elif a == "OBJECT_ID":
                    outfd.write("\n$OBJECT_ID\n")
                    outfd.write(str(i))
                elif a == "ATTRIBUTE_LIST":
                    outfd.write("\n$ATTRIBUTE_LIST " + str(i))
            outfd.write("\n{0}\n".format(border))
