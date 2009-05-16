# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Copyright (C) 2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

from vtypes import xpsp2types as types
from forensics.object import *
from forensics.x86 import x86_native_types
import forensics.registry as MemoryRegistry
import struct

class InvalidType(Exception):
    def __init__(self, typename=None):
        self.typename = typename

    def __str__(self):
        return str(self.typename)

class InvalidMember(Exception):
    def __init__(self, typename=None, membername=None):
        self.typename = typename
        self.membername = membername

    def __str__(self):
        return str(self.typename) + ":" + str(self.membername)

class Object(object):

    def __new__(pcls, theType, offset, vm, parent=None, profile=None):

        theTypeName = None

        if isinstance(theType, str): 
            theTypeName = theType
        elif isinstance(theType, CType):
            theTypeName = theType.name

        # Need to check for any derived object types that may be 
        # found in the global memory registry.
        if theTypeName:
            if MemoryRegistry.OBJECT_CLASSES.objects.has_key(theTypeName):
                return MemoryRegistry.OBJECT_CLASSES[theTypeName](theTypeName, \
                    offset,vm,parent,profile)

        obj = object.__new__(pcls)
        return obj
        
    def __init__(self, theType, offset, vm, parent=None, profile=None, objdefs=None):

        self.vm = vm
        self.members = {}
        self.parent = parent
        self.extra_members = {}
        self.profile = profile
        self.offset = offset

        if offset == None:
            return None

        if not isinstance(theType, str):
            self.type = theType
        elif theType in profile.cstructs:
            self.type = profile.cstructs[theType]
        elif theType in builtin_types and theType != 'pointer':
            self.type = NativeType(profile, theType, \
	        builtin_types[theType][0], builtin_types[theType][1])
        else:
            raise InvalidType,theType
                 
    def __getattribute__(self, attr):

        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            pass

        if attr in self.extra_members:
            return self.extra_members[attr]
       
        if isinstance(self.type, Pointer):
            return self.type.dereference(self)

        if self.type.name in builtin_types:
            raise AttributeError("Native types have no dynamic attributes")

        off = self.get_member_offset(attr, relative=True)
        ObjectMember = self.get_member(attr)

        if off == None or ObjectMember == None:
            raise AttributeError("'%s':no offset or type for attribute '%s'" % \
                (self.type.name, attr))

        if isinstance(ObjectMember.type, Pointer):
            cdecl = ObjectMember.type.basetype.cdecl()
            if cdecl == 'void':
                return Object(ObjectMember.type.basetype, \
                    off+self.offset, self.vm,profile=self.profile)

            base_address = self.get_member(attr).v()
            if base_address == None:
                return None

            return Object(ObjectMember.type.basetype, base_address, \
                self.vm,profile=self.profile)

        elif isinstance(ObjectMember.type, CType): 
            theTypeName = ObjectMember.type.name
            if MemoryRegistry.OBJECT_CLASSES.objects.has_key(ObjectMember.type.name):
                offset = self.offset + off
                return MemoryRegistry.OBJECT_CLASSES[theTypeName](theTypeName,offset,self.vm,self,self.profile)

            return ObjectMember
        elif isinstance(ObjectMember.type,Array): 
            array_vals= []
            for index in ObjectMember.type.get_member_names():
                element = Object(ObjectMember.type.basetype, \
                    ObjectMember.offset + index * \
                    ObjectMember.type.basetype.size, \
                    self.vm,profile=self.profile)
                if isinstance(element.type, NativeType):
                    array_vals.append(element.v())
                else:
                    array_vals.append(element)
            return array_vals
        else:
            return self.get_member(attr).v()
       
    def __eq__(self, other):
        if isinstance(other, Object):
            return (self.type == other.type) and (self.offset == other.offset)
        else:
            return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(self.type.name) ^ hash(self.offset)

    def has_member(self, memname):
        return self.type.hasMembers and self.type.members.has_key(memname)

    def m(self, memname):
        return self.get_member(memname)

    def get_member(self, memname):
        if not self.type.hasMembers:
            return None

        if memname in self.extra_members:
            return self.extra_members[memname]

        if self.members.has_key(memname):
            return self.members[memname]
        else:
            thisMember = self.type.get_member(memname)
            if isinstance(thisMember.type, Pointer) or isinstance(thisMember.type, Array):
                thisObject = Object(thisMember.type, \
		    self.offset + thisMember.offset, self.vm, self,self.profile) 
                return thisObject
            thisObject = Object(thisMember.type.name, \
	        self.offset + thisMember.offset, self.vm, self,self.profile)    
            return thisObject

    def get_member_type(self, memname):
        if self.type.hasMembers:
            thisMemberType = self.type.get_member(memname)
            return thisMemberType
        else:
            return None

    def get_member_offset(self, memname, relative=False): 
        if self.type.hasMembers:
            thisMemberType = self.type.get_member(memname)
            
            if thisMemberType == None:
                return None

            if relative:
                return thisMemberType.offset
            return thisMemberType.offset + self.offset

        else:
            return None

    def is_null(self):
        if isinstance(self.type, Pointer):
            return self.v() == 0x00
        else:
            return False

    def is_valid(self):
        if isinstance(self.type, Pointer):
            if self.v() == None:
                return False
            return self.vm.is_valid_address(self.v())
        elif isinstance(self.type, CType):
            return self.vm.is_valid_address(self.offset)
        else:
            return False

    def dereference(self):
        if isinstance(self.type, Pointer):
            return self.type.dereference(self)
        return None

    def dereference_as(self, castType):
        if isinstance(self.type, Pointer):
            return self.type.dereference_as(castType, self)
        elif isinstance(self.type, Void):
            return self.type.dereference_as(castType, self)
        else:
            return None

    def cast(self, castString):
        if castString in self.type.profile.native_types:
            return Object(castString, self.offset, self.vm, None, self.profile)
        else:
            return Object(castString, self.offset, self.vm, None, self.profile)

    def size(self):
        return self.type.size

    def v(self):
        return self.value()

    def value(self):
        if self.type.hasValue:
            return self.type.v(self)
        elif isinstance(self.type, CType):
            return self.offset
        elif isinstance(self.type, Array):
            array_vals= []
            for index in self.type.get_member_names():
                element = Object(self.type.basetype, \
                    self.offset + index * \
                    self.type.basetype.size, \
                    self.vm,profile=self.profile)
                array_vals.append(element.v())
            return array_vals
        else:
            return None

    def get_member_names(self):
        if self.type.hasMembers:
            return self.type.get_member_names() + self.extra_members.keys()
        else:
            return False

    def get_bytes(self,amount=None):
        if amount == None:
            amount = self.type.size
        return self.vm.read(self.offset, amount)

    def get_values(self):
        value_dict = {}
        for k in self.get_member_names():
            value_dict[k] = self.m(k).v()
        return value_dict

    def __str__(self):
        if  isinstance(self.type, CType):
            retval = "[%s] @ %s" % (self.type.cdecl(), hex(self.offset))
            return retval
        elif isinstance(self.type, Void):
            retval = "[%s]  %s" % (self.type.cdecl(), hex(self.v()))
            return retval
        return object.__str__(self)

    def __repr__(self):
        if isinstance(self.type, NativeType):
            return str(self.value())
        return object.__repr__(self)

class VType:
    def __init__(self, profile, size, hasMembers=False, hasValue=False):
        self.profile = profile
        self.hasMembers=hasMembers
        self.hasValue=hasValue
        self.size = size
    
    def cdecl(self):
        return "VType"

class Void(VType):
    def __init__(self, profile):
        VType.__init__(self, profile, 0, False, True)

    def v(self, theObject):
        return self.value(theObject)

    def value(self, theObject):
        #(val, ) = struct.unpack("=L", theObject.vm.read(theObject.offset, 4))
        tmp = theObject.vm.read(theObject.offset, 4)
        if tmp is None: return None
        (val, ) = struct.unpack("<L", tmp)
        return val

    def cdecl(self):
        return "void"   

    def dereference_as(self, derefType, theObject):
        if isinstance(derefType, str):
            return Object(derefType, self.v(theObject), \
                theObject.vm, None,self.profile)
        return Object(derefType.name, self.v(theObject), theObject.vm, \
            None,self.profile)

class NativeType(VType):
    def __init__(self, profile, name, size, readChar):
        VType.__init__(self, profile, size, False, True)
        self.name = name
        self.size = size
        self.readChar = readChar

    def v(self, theObject):
        return self.value(theObject)

    def value(self, theObject):
        #(val, ) = struct.unpack('='+self.readChar, \
	#    theObject.vm.read(theObject.offset, self.size))
        tmp = theObject.vm.read(theObject.offset, self.size)
        if tmp is None: return None
        (val, ) = struct.unpack('<'+self.readChar, tmp)
        return val

    def cdecl(self):
        return self.name

    def __getattribute__(self, attr):
        return self.v()
        
class Pointer(NativeType):
    def __init__(self, profile, basetype):
        NativeType.__init__(self, profile, 'pointer', profile.native_types['address'].size, \
                            profile.native_types['address'].readChar)
        self.basetype = basetype

    def dereference(self,  theObject):
        return self.dereference_as(self.basetype, theObject)

    def dereference_as(self, derefType, theObject):
        return Object(derefType.name, self.v(theObject), \
	    theObject.vm, None,self.profile)

    def cdecl(self):
        return "%s *" % self.basetype.cdecl()

    def __repr__(self):
        return "<pointer to [%s ]>" % (self.basetype.cdecl())

    def __getattribute__(self, attr):
        try:
            return super(Pointer,self).__getattribute__(attr)
        except AttributeError:
            return getattr(self.value, attr)

class CTypeMember:
    def __init__(self, name, offset, theType):
        self.name = name
        self.offset = offset
        self.type = theType
        
class CType(VType):
    def __init__(self, profile, name, size, members, isStruct):
        VType.__init__(self, profile, size, True, False)
        self.name = name
        self.members = members
        self.isStruct = isStruct

    def add_member(self, name, member):
        self.members[member.name] = member

    def set_members(self, members):
        self.members = members

    def get_member_names(self):
        return self.members.keys()

    def get_member_type(self, memname):
        return self.members[memname].type

    def get_member_offset(self, memname):
        return self.members[memname].offset

    def get_member(self, memname):
        return self.members[memname]

    def is_struct(self):
        return self.isStruct

    def cdecl(self):
        if self.isStruct:
            return "struct %s" % self.name
        else:
            return "union %s" % self.name

class Array(VType):
    def __init__(self, profile, count, basetype):
        VType.__init__(self, profile, count * basetype.size, True, False)
        self.count = count
        self.basetype = basetype

    def get_member_names(self):
        return range(0, self.count)

    def get_member(self, index):
        return CTypeMember(index, self.basetype.size * index, self.basetype)

    def cdecl(self):
        return "%s[%d]" % (self.basetype.cdecl(), self.count)     

## Profiles are the interface for creating/interpreting
## objects

class Profile:
    def __init__(self, native_types=x86_native_types):
        self.native_types = {}
        self.cstructs = {}
        globs = {}
        locs = {}
        self.voidType = Void(self)

        # Load the native types
        for nt in native_types.keys():
            self.native_types[nt] = NativeType(self, nt, \
	        native_types[nt][0], native_types[nt][1])
       
        # Load the abstract data types
        typeDict = types
        for ctype in typeDict.keys():
           self.import_type(ctype, typeDict)
	
    def import_type(self, ctype, typeDict):
        members = self.convert_members(ctype, typeDict)
        if self.cstructs.has_key(ctype):
            self.cstructs[ctype].set_members(members)
            self.cstructs[ctype].size = typeDict[ctype][0]
        else:
            isStruct = (ctype.find('union') == -1)
            self.cstructs[ctype] = CType(self, ctype, typeDict[ctype][0], members, isStruct)

    def add_types(self, addDict):
        for ctype in addDict.keys():
            self.import_type(ctype, addDict)
        
    def list_to_type(self, typeList, typeDict):
        if typeList[0] == 'void':
            return self.voidType        
        if typeList[0] == 'pointer':
            return Pointer(self, self.list_to_type(typeList[1], typeDict))
        if typeList[0] == 'array':
            return Array(self, typeList[1], self.list_to_type(typeList[2], typeDict))
        if self.native_types.has_key(typeList[0]):
            return self.native_types[typeList[0]]
        if self.cstructs.has_key(typeList[0]):
            return self.cstructs[typeList[0]]

        isStruct = (typeList[0].find('union') == -1)
        self.cstructs[typeList[0]] = CType(self, typeList[0], 0, {}, isStruct)
        return self.cstructs[typeList[0]]        
        
    def convert_members(self, cname, typeDict):
        ctype = typeDict[cname]
        members = {}
        for i in ctype[1].keys():
            members[i] = CTypeMember(i, ctype[1][i][0], self.list_to_type(ctype[1][i][1], typeDict))
        return members
