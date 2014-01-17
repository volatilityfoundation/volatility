# VMware snapshot file parser
# Copyright (C) 2012 Nir Izraeli (nirizr at gmail dot com)
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
@author:       Nir Izraeli
@license:      GNU General Public License 2.0
@contact:      nirizr@gmail.com

This Address Space for Volatility is based on Nir's vmsnparser:
http://code.google.com/p/vmsnparser. It was converted by MHL. 
"""

import volatility.addrspace as addrspace
import volatility.obj as obj

class _VMWARE_HEADER(obj.CType):
    """A class for VMware VMSS/VMSN files"""

    @property
    def Version(self):
        """The vmss/vmsn storage format version"""
        return self.Magic & 0xF

class _VMWARE_GROUP(obj.CType):
    """A class for VMware Groups"""

    def _get_header(self):
        """Lookup the parent VMware header object"""

        parent = self.obj_parent
        while parent.obj_name != '_VMWARE_HEADER':
            parent = parent.obj_parent

        return parent

    @property
    def Tags(self):
        """Generator for tags objects"""

        tag = obj.Object("_VMWARE_TAG", offset = self.TagsOffset,
                         vm = self.obj_vm, parent = self._get_header())

        while not (tag.Flags == 0 and tag.NameLength == 0):
            yield tag
            ## Determine the address of the next tag  
            tag = obj.Object("_VMWARE_TAG", vm = self.obj_vm,
                             parent = self._get_header(),
                             offset = tag.RealDataOffset + tag.DataDiskSize)

class _VMWARE_TAG(obj.CType):
    """A class for VMware Tags"""

    def _size_type(self):
        """Depending on the version, the 'real' data size field is 
        either 4 or 8 bytes"""

        if self.obj_parent.Version == 0:
            obj_type = 'unsigned int'
        else:
            obj_type = 'unsigned long long'

        return obj_type

    @property
    def OriginalDataOffset(self):
        """Determine the offset to this tag's data"""
        return (self.Name.obj_offset + self.NameLength +
               (self.TagIndices.count * self.obj_vm.profile.get_obj_size("unsigned int")))

    @property
    def RealDataOffset(self):
        """Determine the real offset to this tag's data"""

        if self.OriginalDataSize in (62, 63):
            ## Add the original offset plus the two 32- or 64-bit lengths
            offset = (self.OriginalDataOffset +
                     (self.obj_vm.profile.get_obj_size(self._size_type()) * 2))
            ## There is a 16-bit padding value
            padlen = obj.Object("unsigned short", offset = offset, vm = self.obj_vm)
            ## Final result is the offset after the pad, plus the padding value
            return offset + 2 + padlen
        else:
            return self.OriginalDataOffset

    @property
    def OriginalDataSize(self):
        return self.Flags & 0x3F

    @property
    def DataDiskSize(self):
        """Get the tag's data size on disk"""

        # these are special data sizes that signal a longer data stream
        if self.OriginalDataSize in (62, 63):
            return obj.Object(self._size_type(), offset = self.OriginalDataOffset,
                              vm = self.obj_vm)
        else:
            return self.OriginalDataSize

    @property
    def DataMemSize(self):
        """Get the tag's data size in memory"""

        if self.OriginalDataSize in (62, 63):
            return obj.Object(self._size_type(),
                              offset = self.OriginalDataOffset + \
                              self.obj_vm.profile.get_obj_size(self._size_type()),
                              vm = self.obj_vm)
        else:
            return self.OriginalDataSize

    def cast_as(self, cast_type):
        """Cast the data in a tag as a specific type"""

        return obj.Object(cast_type, offset = self.RealDataOffset,
                          vm = self.obj_vm)

class VMwareVTypesModification(obj.ProfileModification):
    """Apply the necessary VTypes for parsing VMware headers"""

    def modification(self, profile):
        profile.vtypes.update({
            '_VMWARE_HEADER' : [ 12, {
                'Magic' : [ 0, ['unsigned int']],
                'GroupCount' : [ 8, ['unsigned int']],
                'Groups' : [ 12, ['array', lambda x : x.GroupCount, ['_VMWARE_GROUP']]],
            }],
            '_VMWARE_GROUP' : [ 80, {
                'Name' : [ 0, ['String', dict(length = 64, encoding = 'utf8')]],
                'TagsOffset' : [ 64, ['unsigned long long']],
            }],
            '_VMWARE_TAG' : [ None, {
                'Flags' : [ 0, ['unsigned char']],
                'NameLength' : [ 1, ['unsigned char']],
                'Name' : [ 2, ['String', dict(length = lambda x : x.NameLength, encoding = 'utf8')]],
                'TagIndices' : [ lambda x : x.obj_offset + 2 + x.NameLength, ['array', lambda x : (x.Flags >> 6) & 0x3, ['unsigned int']]],
            }],
        })
        profile.object_classes.update({
            '_VMWARE_HEADER': _VMWARE_HEADER,
            '_VMWARE_GROUP': _VMWARE_GROUP,
            '_VMWARE_TAG': _VMWARE_TAG
            })

class VMWareSnapshotFile(addrspace.AbstractRunBasedMemory):
    """ This AS supports VMware snapshot files """

    order = 30
    PAGE_SIZE = 4096

    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)

        ## This is a tuple of (physical memory offset, file offset, length)
        self.runs = []

        ## A VMware header is found at offset zero of the file 
        self.header = obj.Object("_VMWARE_HEADER", offset = 0, vm = base)

        self.as_assert(self.header.Magic in [0xbed2bed0, 0xbad1bad1, 0xbed2bed2, 0xbed3bed3],
                       "Invalid VMware signature: {0:#x}".format(self.header.Magic))

        ## The number of memory regions contained in the file 
        region_count = self._get_tag(grp_name = "memory",
                                     tag_name = "regionsCount", data_type = "unsigned int")

        if not region_count.is_valid() or region_count == 0:
            ## Create a single run from the main memory region 
            memory_tag = self._get_tag(grp_name = "memory", tag_name = "Memory")

            self.as_assert(memory_tag is not None,
                           "Cannot find the single-region Memory tag")

            self.runs.append((0, memory_tag.RealDataOffset, memory_tag.DataDiskSize))
        else:
            ## Create multiple runs - one for each region in the header
            for i in range(region_count):
                memory_tag = self._get_tag(grp_name = "memory", tag_name = "Memory",
                                indices = [0, 0])

                memory_offset = self._get_tag(grp_name = "memory", tag_name = "regionPPN",
                                indices = [i],
                                data_type = "unsigned int") * self.PAGE_SIZE

                file_offset = self._get_tag(grp_name = "memory",
                                tag_name = "regionPageNum", indices = [i],
                                data_type = "unsigned int") * \
                                self.PAGE_SIZE + memory_tag.RealDataOffset

                length = self._get_tag(grp_name = "memory", tag_name = "regionSize",
                                indices = [i],
                                data_type = "unsigned int") * self.PAGE_SIZE

                self.runs.append((memory_offset, file_offset, length))

        ## Make sure we found at least one memory run
        self.as_assert(len(self.runs) > 0,
                       "Cannot find any memory run information")

        ## Find the DTB from CR3. For x86 we grab an int from CR and 
        ## for x64 we grab a long long from CR64.
        if self.profile.metadata.get("memory_model", "32bit") == "32bit":
            self.dtb = self._get_tag(grp_name = "cpu", tag_name = "CR",
                                 indices = [0, 3],
                                 data_type = "unsigned int")
        else:
            self.dtb = self._get_tag(grp_name = "cpu", tag_name = "CR64",
                                indices = [0, 3],
                                data_type = "unsigned long long")

        self.as_assert(self.dtb is not None, "Cannot find a DTB")

    def _get_tag(self, grp_name, tag_name, indices = None, data_type = None):
        """Get a tag from the VMware headers
        
        @param grp_name: the group name (from _VMWARE_GROUP.Name)
        
        @param tag_name: the tag name (from _VMWARE_TAG.Name)
        
        @param indices: a group can contain multiple tags of the same name, 
        and tags can also contain meta-tags. this parameter lets you specify 
        which tag or meta-tag exactly to operate on. for example the 3rd CR 
        register (CR3) of the first CPU would use [0][3] indices. If this 
        parameter is None, then you just match on grp_name and tag_name. 
        
        @param data_type: the type of data depends on the purpose of the tag. 
        If you supply this parameter, the function returns an object of the 
        specified type (for example an int or long). If not supplied, you just 
        get back the _VMWARE_TAG object itself. 
        """

        for group in self.header.Groups:
            ## Match on the group's name
            if str(group.Name) != grp_name:
                continue
            ## Iterate the tags looking for a matchah 
            for tag in group.Tags:
                if str(tag.Name) != tag_name:
                    continue
                ## If a set of indices was supplied, make sure it matches
                if indices and tag.TagIndices != indices:
                    continue
                ## If a data type is specified, cast the Tag and return the 
                ## object. Otherwise return the Tag object itself. 
                if data_type:
                    return tag.cast_as(data_type)
                else:
                    return tag

        return obj.NoneObject("Cannot find [{0}][{1}]".format(grp_name, tag_name))
