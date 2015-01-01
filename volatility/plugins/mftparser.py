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
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.debug as debug
import struct
import binascii
import os
import volatility.poolscan as poolscan

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
    def __init__(self, *args, **kwargs):
        # Usually we don't add members to objects like this, but its an
        # exception due to lack of better options.
        obj.CType.__init__(self, *args, **kwargs)
        self.newattr("stdinfo", None)
        self.newattr("fnlong", None)
        self.newattr("fnshort", None)
        self.newattr("objectid", None)
        self.newattr("data", [])
        self.newattr("esize", 1024)
        self.newattr("check", True)
        self.newattr("mft_buff", self.obj_vm.read(self.obj_offset, self.esize))
        end = self.mft_buff.find("\xff\xff\xff\xff")
        if end == -1:
            end = int(self.esize)
        self.newattr("end", end + int(self.obj_offset))
        self.parse_attributes(entrysize = self.esize)

    def set_options(self, esize = 1024, check = True):
        # this function allows us to have entries larger than 1K
        self.newattr("esize", esize)
        if check in [True, False]:
            self.newattr("check", check)
        self.newattr("mft_buff", self.obj_vm.read(self.obj_offset, self.esize))
        end = self.mft_buff.find("\xff\xff\xff\xff")
        if end == -1:
            end = int(self.esize)
        self.newattr("end", end + int(self.obj_offset))
        self.parse_attributes(entrysize = self.esize, check = self.check)

    def remove_unprintable(self, str):
        return ''.join([c for c in str if (ord(c) > 31 or ord(c) == 9) and ord(c) <= 126])

    def add_path(self, fileinfo):
        # it doesn't really make sense to add regular files to parent directory,
        # since they wouldn't actually be in the middle of a file path, but at the end
        # therefore, we'll return for regular files
        if not self.is_directory():
            return
        # otherwise keep a record of the directory that we've found
        cur = MFT_PATHS_FULL.get(int(self.RecordNumber), None)
        if (cur == None or int(fileinfo.Namespace) in [0, 1, 3]) and fileinfo.is_valid():
            temp = {}
            temp["ParentDirectory"] = fileinfo.ParentDirectory
            temp["filename"] = self.remove_unprintable(fileinfo.get_name())
            MFT_PATHS_FULL[int(self.RecordNumber)] = temp

    def get_full_path(self):
        fileinfo = self.fnlong or self.fnshort
        if fileinfo == None:
            return "(Null)"
        if hasattr(self.obj_vm._config, "DEBUGOUT") and self.obj_vm._config.DEBUGOUT:
            print "Building path for file {0}".format(fileinfo.get_name())
        parent = ""
        path = self.remove_unprintable(fileinfo.get_name()) or "(Null)"
        try:
            parent_id = fileinfo.ParentDirectory & 0xffffff
        except struct.error:
            return path
        if int(self.RecordNumber) == 5 or int(self.RecordNumber) == 0:
            return path
        seen = set()
        while parent != {}:
            seen.add(parent_id)
            parent = MFT_PATHS_FULL.get(int(parent_id), {})
            if parent == {} or parent["filename"] == "" or int(parent_id) == 0 or int(parent_id) == 5:
                return path
            path = "{0}\\{1}".format(parent["filename"], path)
            parent_id = parent["ParentDirectory"] & 0xffffff
            if parent_id in seen:
                return path
        return path

    def is_directory(self):
        return int(self.Flags) & 0x2

    def is_file(self):
        return int(self.Flags) & 0x2 == 0

    def is_inuse(self):
        return int(self.Flags) & 0x1 == 0x1

    def get_mft_type(self):
        return "{0}{1}".format("In Use & " if self.is_inuse() else "",
               "Directory" if self.is_directory() else "File")

    # We want to be able to differenciate between a $FN attribute that is 8.3
    # and the full readable file name.  We prefer the latter for building paths
    def add_filename(self, fn):
        if fn.Namespace == 2:
            self.newattr("fnshort", fn)
            if hasattr(self.obj_vm._config, "DEBUGOUT") and self.obj_vm._config.DEBUGOUT:
                print "added", fn.get_name()
        else:
            self.newattr("fnlong", fn)
            if hasattr(self.obj_vm._config, "DEBUGOUT") and self.obj_vm._config.DEBUGOUT:
                print "added (long)", fn.get_name()

    def process_attr_list(self, next_attr, attributes = [], check = True):
        start = 0
        end = self.end
        while start < end:
            item = obj.Object("ATTRIBUTE_LIST", vm = self.obj_vm,
                                offset = next_attr.AttributeList.obj_offset + start)
            if item == None:
                return
            try:
                thetype = ATTRIBUTE_TYPE_ID.get(int(item.Type), None)
                if thetype == None:
                    return
                elif item.Length > 0x20 and thetype in ["STANDARD_INFORMATION", "FILE_NAME"]:
                    theitem = obj.Object(thetype, vm = self.obj_vm, offset = item.AttributeID.obj_offset)
                    if thetype == "STANDARD_INFORMATION" and (not check or theitem.is_valid()):
                        attributes.append(("STANDARD_INFORMATION (AL)", theitem))
                    elif thetype == "FILE_NAME" and (not check or theitem.is_valid()):
                        self.add_path(theitem)
                        self.add_filename(theitem)
                        attributes.append(("FILE_NAME (AL)", theitem))
            except struct.error:
                return
            if item.Length <= 0:
                return
            start += item.Length

    def parse_attributes(self, check = True, entrysize = 1024):
        next_attr = self.ResidentAttributes
        end = self.end
        attributes = []
        dataseen = False
        while next_attr != None and next_attr.obj_offset <= end:
            try:
                attr = ATTRIBUTE_TYPE_ID.get(int(next_attr.Header.Type), None)
            except struct.error:
                next_attr = None
                attr = None
                continue
            if attr == None:
                next_attr = None
            elif attr == "STANDARD_INFORMATION":
                if hasattr(self.obj_vm._config, "DEBUGOUT") and self.obj_vm._config.DEBUGOUT:
                    print "Found $SI"
                if not check or next_attr.STDInfo.is_valid():
                    attributes.append((attr, next_attr.STDInfo))
                    self.newattr("stdinfo", next_attr.STDInfo)
                next_off = next_attr.STDInfo.obj_offset + next_attr.ContentSize
                if next_off == next_attr.STDInfo.obj_offset:
                    next_attr = None
                    continue
                next_attr = self.advance_one(next_off)
            elif attr == 'FILE_NAME':
                if hasattr(self.obj_vm._config, "DEBUGOUT") and self.obj_vm._config.DEBUGOUT:
                    print "Found $FN"
                self.add_path(next_attr.FileName)
                if not check or next_attr.FileName.is_valid():
                    attributes.append((attr, next_attr.FileName))
                    self.add_filename(next_attr.FileName)
                next_off = next_attr.FileName.obj_offset + next_attr.ContentSize
                if next_off == next_attr.FileName.obj_offset:
                    next_attr = None
                    continue
                next_attr = self.advance_one(next_off)
            elif attr == "OBJECT_ID":
                if hasattr(self.obj_vm._config, "DEBUGOUT") and self.obj_vm._config.DEBUGOUT:
                    print "Found $ObjectId"
                if next_attr.Header.NonResidentFlag == 1:
                    attributes.append((attr, "Non-Resident"))
                    next_attr = None
                    continue
                else:
                    attributes.append((attr, next_attr.ObjectID))
                    self.newattr("objectid", next_attr.ObjectID)
                next_off = next_attr.ObjectID.obj_offset + next_attr.ContentSize
                if next_off == next_attr.ObjectID.obj_offset:
                    next_attr = None
                    continue
                next_attr = self.advance_one(next_off)
            elif attr == "DATA":
                if hasattr(self.obj_vm._config, "DEBUGOUT") and self.obj_vm._config.DEBUGOUT:
                    print "Found $DATA"
                try:
                    if next_attr.Header and next_attr.Header.NameOffset > 0 and next_attr.Header.NameLength > 0:
                        adsname = ""
                        if next_attr != None and next_attr.Header != None and next_attr.Header.NameOffset and next_attr.Header.NameLength:
                            adsname = next_attr.ADSName
                            if adsname != None and adsname.strip() != "" and dataseen:
                                attr += " ADS Name: {0}".format(adsname.strip())
                    dataseen = True
                except struct.error:
                    next_attr = None
                    continue
                try:
                    if next_attr.Header.NonResidentFlag == 1 or next_attr.ContentSize == 0:
                        next_off = next_attr.obj_offset + self.obj_vm.profile.get_obj_size("RESIDENT_ATTRIBUTE")
                        next_attr = self.advance_one(next_off)
                        attributes.append((attr, ""))
                        continue
                    start = (next_attr.obj_offset + next_attr.ContentOffset) - self.obj_offset
                    theend = min(start + next_attr.ContentSize, (end - self.obj_offset))
                except struct.error:
                    next_attr = None
                    continue
                attributes.append((attr, next_attr.Data))
                if next_attr not in self.data:
                    self.data.append(next_attr)
                next_off = theend + self.obj_offset
                if next_off == start:
                    next_attr = None
                    continue
                next_attr = self.advance_one(next_off)
            elif attr == "ATTRIBUTE_LIST":
                if hasattr(self.obj_vm._config, "DEBUGOUT") and self.obj_vm._config.DEBUGOUT:
                    print "Found $AttributeList"
                if next_attr.Header.NonResidentFlag == 1:
                    attributes.append((attr, "Non-Resident"))
                    next_attr = None
                    continue
                self.process_attr_list(next_attr, attributes, check)
                next_attr = None
            else:
                next_attr = None
        return attributes

    def advance_one(self, next_off, end = None):
        item = None
        attr = None
        cursor = 0

        if next_off == None:
            return None
        while attr == None and cursor <= (self.end - next_off):
            try:
                start = (next_off + cursor) - self.obj_offset
                end = (next_off + cursor + 4) - self.obj_offset
                val = struct.unpack("<I", self.mft_buff[start: end])[0]
                attr = ATTRIBUTE_TYPE_ID.get(val, None)
                item = obj.Object('RESIDENT_ATTRIBUTE', vm = self.obj_vm,
                            offset = next_off + cursor)
            except struct.error:
                return None
            cursor += 1
        return item

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
        if self.Flags == None:
            return "?"
        type = ""
        for i, j in sorted(SHORT_STANDARD_INFO_FLAGS.items()):
            if i & self.Flags == i:
                type += j
            else:
                type += "-"
        return type


    def get_type(self):
        if self.Flags == None:
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
        return "{0:20} {1:30} {2:30} {3:30} {4}".format(str(self.CreationTime),
            str(self.ModifiedTime),
            str(self.MFTAlteredTime),
            str(self.FileAccessedTime),
            self.get_type())

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

        return "[{9}MFT STD_INFO] {0} (Offset: 0x{1:x})|{2}|{3}|0|0|{4}|{5}|{6}|{7}|{8}".format(
            path,
            offset,
            record_num,
            self.get_type_short(),
            size,
            self.FileAccessedTime.v(),
            self.ModifiedTime.v(),
            self.MFTAlteredTime.v(),
            self.CreationTime.v(),
            self.obj_vm._config.MACHINE)

class FILE_NAME(STANDARD_INFORMATION):
    def remove_unprintable(self, str):
        return ''.join([c for c in str if (ord(c) > 31 or ord(c) == 9) and ord(c) <= 126])

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
                accessed != 0 or creation != 0) and \
                self.remove_unprintable(self.get_name()) != ""

    def get_name(self):
        if self.NameLength == None or self.NameLength == 0:
            return ""
        return "{0}".format(str(self.Name).replace("\x00", ""))

    def get_header(self):
        return [("Creation", "30"),
                ("Modified", "30"),
                ("MFT Altered", "30"),
                ("Access Date", "30"),
                ("Name/Path", ""),
               ]

    def __str__(self):
        return "{0:20} {1:30} {2:30} {3:30} {4}".format(str(self.CreationTime),
            str(self.ModifiedTime),
            str(self.MFTAlteredTime),
            str(self.FileAccessedTime),
            self.remove_unprintable(self.get_name()))

    def get_full(self, full):
        try:
            return "{0:20} {1:30} {2:30} {3:30} {4}".format(str(self.CreationTime),
                str(self.ModifiedTime),
                str(self.MFTAlteredTime),
                str(self.FileAccessedTime),
                self.remove_unprintable(full))
        except struct.error:
            return None

    def body(self, path, record_num, size, offset):
        return "[{9}MFT FILE_NAME] {0} (Offset: 0x{1:x})|{2}|{3}|0|0|{4}|{5}|{6}|{7}|{8}".format(
            path,
            offset,
            record_num,
            self.get_type_short(),
            size,
            self.FileAccessedTime.v(),
            self.ModifiedTime.v(),
            self.MFTAlteredTime.v(),
            self.CreationTime.v(),
            self.obj_vm._config.MACHINE)

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
        'STDInfo': lambda x : obj.Object("STANDARD_INFORMATION", offset = x.obj_offset + x.ContentOffset, vm = x.obj_vm),
        'FileName': lambda x : obj.Object("FILE_NAME", offset = x.obj_offset + x.ContentOffset, vm = x.obj_vm),
        'ObjectID': lambda x : obj.Object("OBJECT_ID", offset = x.obj_offset + x.ContentOffset, vm = x.obj_vm),
        'AttributeList':lambda x : obj.Object("ATTRIBUTE_LIST", offset = x.obj_offset + x.ContentOffset, vm = x.obj_vm),
        # may need to rethink the maximum size of a $DATA attribute, but for now we'll use this
        'Data' : lambda x: x.obj_vm.read(x.obj_offset + x.ContentOffset, min(x.ContentSize, 1024)),
        'ADSName': lambda x: obj.Object("NullString", vm = x.obj_vm, offset = x.obj_offset + x.Header.NameOffset, length = x.Header.NameLength * 2),
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
        'Name': [0x42, ['NullString', dict(length = lambda x: x.NameLength * 2)]],
    }],

    'ATTRIBUTE_LIST': [0x19, {
        'Type': [0x0, ['unsigned int']],
        'Length': [0x4, ['unsigned short']],
        'NameLength': [0x6, ['unsigned char']],
        'NameOffset': [0x7, ['unsigned char']],
        'StartingVCN': [0x8, ['unigned long long']],
        'FileReferenceLocation': [0x10, ['unsigned long long']],
        'AttributeID': [0x18, ['unsigned char']],
    }],

    'OBJECT_ID': [0x40, {
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
            'MFT_FILE_RECORD':MFT_FILE_RECORD,
            'FILE_NAME':FILE_NAME,
            'STANDARD_INFORMATION':STANDARD_INFORMATION,
            'OBJECT_ID':OBJECT_ID,
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
                mft_entry = obj.Object('MFT_FILE_RECORD', vm = address_space, offset = offset)
                if self._config.ENTRYSIZE != 1024 or self._config.NOCHECK:
                    mft_entry.set_options(esize = self._config.ENTRYSIZE, check = not self._config.NOCHECK)
                offsets.append((offset, mft_entry))
        else:
            scanner = poolscan.MultiPoolScanner(needles = ['FILE', 'BAAD'])
            print "Scanning for MFT entries and building directory, this can take a while"
            seen = []
            for _, offset in scanner.scan(address_space):
                try:
                    mft_entry = obj.Object('MFT_FILE_RECORD', vm = address_space, offset = offset)
                    if self._config.ENTRYSIZE != 1024:
                        mft_entry.set_size(self._config.ENTRYSIZE)
                except struct.error:
                    if self._config.DEBUGOUT:
                        print "Problem entry at offset:", hex(offset)
                name = mft_entry.fnlong or mft_entry.fnshort
                if name == None or (int(mft_entry.RecordNumber), name) in seen:
                    continue
                else:
                    seen.append((int(mft_entry.RecordNumber), name))
                offsets.append((offset, mft_entry))

        # The reason why we wait until the end to yield the mft entries is so that we 
        # are able to build the entire path.  Unlike disk, we are not able to depend on
        # entries to be in order
        for offset, mft_entry in offsets:
            if self._config.DEBUGOUT:
                print "Processing MFT Entry at offset:", hex(offset)
            yield offset, mft_entry

    def render_body(self, outfd, data):
        if self._config.DUMP_DIR != None and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")
        # Some notes: every base MFT entry should have one $SI and at lease one $FN
        # Usually $SI occurs before $FN
        # We'll make an effort to get the filename from $FN for $SI
        # If there is only one $SI with no $FN we dump whatever information it has
        for offset, mft_entry in data:
            # we'll have a default file size of -1 for records missing $FN attributes
            # note that file size found in $FN may not actually be accurate and will most likely
            # be 0.  See Carrier, pg 363
            size = -1
            fn = None
            full = mft_entry.get_full_path()
            if mft_entry.fnlong or mft_entry.fnshort:
                fn = mft_entry.fnlong or mft_entry.fnshort
                size = int(fn.RealFileSize)
                if mft_entry.stdinfo:
                    outfd.write("0|{0}\n".format(mft_entry.stdinfo.body(full, mft_entry.RecordNumber, size, offset)))
            else:
                # here we have a lone $SI in an MFT entry with no valid $FN.  This is most likely a non-base entry
                outfd.write("0|{0}\n".format(mft_entry.stdinfo.body("", mft_entry.RecordNumber, -1, offset)))
            datanum = 0
            allads = " ADSNames: "
            for d in mft_entry.data:
                ads = ""
                if d.ADSName.strip() != "":
                    ads = "({0}) ".format(mft_entry.remove_unprintable(str(d.ADSName.strip())))
                    allads += ads
                if len(str(d.Data)) > 0:
                    file_string = ".".join(["file", "0x{0:x}".format(offset), "data{0}{1}".format(datanum, ads), "dmp"])
                    datanum += 1
                    if self._config.DUMP_DIR != None:
                        of_path = os.path.join(self._config.DUMP_DIR, file_string)
                        of = open(of_path, 'wb')
                        of.write(d.Data)
                        of.close()
            if allads == " ADSNames: ":
                allads = ""
            if mft_entry.fnlong:
                outfd.write("0|{0}\n".format(mft_entry.fnlong.body(full + allads, mft_entry.RecordNumber, size, offset)))
            if mft_entry.fnshort:
                outfd.write("0|{0}\n".format(mft_entry.fnshort.body(full + allads, mft_entry.RecordNumber, size, offset)))


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
        for offset, mft_entry in data:
            datnum = 0
            if mft_entry.stdinfo:
                attrdata = ["STANDARD_INFORMATION", str(mft_entry.stdinfo.CreationTime),
                                str(mft_entry.stdinfo.ModifiedTime),
                                str(mft_entry.stdinfo.MFTAlteredTime),
                                str(mft_entry.stdinfo.FileAccessedTime),
                                mft_entry.stdinfo.get_type()]
                yield (0, [Address(offset),
                           str(mft_entry.get_mft_type()),
                           int(mft_entry.RecordNumber),
                           int(mft_entry.LinkCount)] + attrdata)
            if mft_entry.fnshort:
                attrdata = ["FILE_NAME", str(mft_entry.fnshort.CreationTime),
                                str(mft_entry.fnshort.ModifiedTime),
                                str(mft_entry.fnshort.MFTAlteredTime),
                                str(mft_entry.fnshort.FileAccessedTime),
                                mft_entry.fnshort.remove_unprintable(mft_entry.fnshort.get_name())]
                yield (0, [Address(offset),
                           str(mft_entry.get_mft_type()),
                           int(mft_entry.RecordNumber),
                           int(mft_entry.LinkCount)] + attrdata)
            if mft_entry.fnlong:
                attrdata = ["FILE_NAME", str(mft_entry.fnlong.CreationTime),
                                str(mft_entry.fnlong.ModifiedTime),
                                str(mft_entry.fnlong.MFTAlteredTime),
                                str(mft_entry.fnlong.FileAccessedTime),
                                mft_entry.fnlong.remove_unprintable(mft_entry.fnlong.get_name())]
                yield (0, [Address(offset),
                           str(mft_entry.get_mft_type()),
                           int(mft_entry.RecordNumber),
                           int(mft_entry.LinkCount)] + attrdata)


    def render_text(self, outfd, data):
        if self._config.DUMP_DIR != None and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")
        border = "*" * 75
        for offset, mft_entry in data:
            outfd.write("{0}\n".format(border))
            outfd.write("MFT entry found at offset 0x{0:x}\n".format(offset))
            outfd.write("Attribute: {0}\n".format(mft_entry.get_mft_type()))
            outfd.write("Record Number: {0}\n".format(mft_entry.RecordNumber))
            outfd.write("Link count: {0}\n".format(mft_entry.LinkCount))
            outfd.write("\n")
            # there can be more than one resident $DATA attribute
            # e.g. ADS.  Therfore we need to differentiate somehow
            # to avoid clobbering.  For now we'll use a counter (datanum)
            datanum = 0
            size = -1
            fn = None
            if mft_entry.stdinfo:
                outfd.write("\n${0}\n".format("STANDARD_INFORMATION"))
                self.table_header(outfd, mft_entry.stdinfo.get_header())
                outfd.write("{0}\n".format(str(mft_entry.stdinfo)))
            full = mft_entry.get_full_path()
            if full and mft_entry.fnlong:
                outfd.write("\n${0}\n".format("FILE_NAME"))
                if hasattr(mft_entry.fnlong, "ParentDirectory"):
                    self.table_header(outfd, mft_entry.fnlong.get_header())
                    output = mft_entry.fnlong.get_full(full)
                    if output == None:
                        continue
                    outfd.write("{0}\n".format(output))
                else:
                    outfd.write("{0}\n".format(str(mft_entry.fnlong)))
            if full and mft_entry.fnshort:
                outfd.write("\n${0}\n".format("FILE_NAME"))
                if hasattr(mft_entry.fnshort, "ParentDirectory"):
                    self.table_header(outfd, mft_entry.fnshort.get_header())
                    output = mft_entry.fnshort.get_full(full)
                    if output == None:
                        continue
                    outfd.write("{0}\n".format(output))
                else:
                    outfd.write("{0}\n".format(str(mft_entry.fnshort)))
            for d in mft_entry.data:
                ads = ""
                if d.ADSName.strip() != "":
                    ads = " ADS Name: {0}".format(mft_entry.remove_unprintable(str(d.ADSName.strip())))
                outfd.write("\n${0}{1}\n".format("DATA", ads))
                contents = "\n".join(["{0:010x}: {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(d.Data)])
                outfd.write("{0}\n".format(str(contents)))
                if len(str(d.Data)) > 0:
                    file_string = ".".join(["file", "0x{0:x}".format(offset), "data{0}{1}".format(datanum, ads), "dmp"])
                    datanum += 1
                    if self._config.DUMP_DIR != None:
                        of_path = os.path.join(self._config.DUMP_DIR, file_string)
                        of = open(of_path, 'wb')
                        of.write(d.Data)
                        of.close()
            outfd.write("\n$OBJECT_ID\n")
            outfd.write(str(mft_entry.objectid))
            outfd.write("\n{0}\n".format(border))
