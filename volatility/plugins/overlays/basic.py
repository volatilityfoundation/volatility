# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
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

""" This file defines some basic types which might be useful for many
OS's
"""
import copy
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.constants as constants

## The following is a conversion of basic C99 types to python struct
## format strings. NOTE: since volatility is analysing images which
## are not necessarily the same bit size as the currently running
## platform you may not use platform specific format specifiers here
## like l or L - you must use i or I.
x86_native_types = {
    'int' : [4, '<i'],
    'long': [4, '<i'],
    'unsigned long' : [4, '<I'],
    'unsigned int' : [4, '<I'],
    'address' : [4, '<I'],
    'char' : [1, '<c'],
    'unsigned char' : [1, '<B'],
    'unsigned short int' : [2, '<H'],
    'unsigned short' : [2, '<H'],
    'unsigned be short' : [2, '>H'],
    'short' : [2, '<h'],
    'long long' : [8, '<q'],
    'unsigned long long' : [8, '<Q'],
    }

x64_native_types = copy.deepcopy(x86_native_types)
x64_native_types['address'] = [8, '<Q']
x64_native_types['pointer64'] = [8, '<Q']

class String(obj.NativeType):
    """Class for dealing with Strings"""
    def __init__(self, theType, offset, vm = None,
                 length = 1, parent = None, profile = None, **kwargs):
        ## Allow length to be a callable:
        if callable(length):
            length = length(parent)

        self.length = length

        ## length must be an integer
        obj.NativeType.__init__(self, theType, offset, vm, parent = parent, profile = profile,
                                format_string = "{0}s".format(length), **kwargs)

    def proxied(self, name):
        """ Return an object to be proxied """
        return self.__str__()

    def __str__(self):
        data = self.v()
        ## Make sure its null terminated:
        result = data.split("\x00")[0]
        if not result:
            return ""
        return result

    def __format__(self, formatspec):
        return format(self.__str__(), formatspec)

    def __add__(self, other):
        """Set up mappings for concat"""
        return str(self) + other

    def __radd__(self, other):
        """Set up mappings for reverse concat"""
        return other + str(self)

obj.Profile.object_classes['String'] = String

class Flags(obj.NativeType):
    """ This object decodes each flag into a string """
    ## This dictionary maps each bit to a String
    bitmap = None

    ## This dictionary maps a string mask name to a bit range
    ## consisting of a list of start, width bits
    maskmap = None

    def __init__(self, theType = None, offset = 0, vm = None, parent = None,
                 bitmap = None, maskmap = None, target = "unsigned long",
                 **kwargs):
        self.bitmap = bitmap or {}
        self.maskmap = maskmap or {}
        self.target = target

        self.target_obj = obj.Object(target, offset = offset, vm = vm, parent = parent)
        obj.NativeType.__init__(self, theType, offset, vm, parent, **kwargs)

    def v(self):
        return self.target_obj.v()

    def __str__(self):
        result = []
        value = self.v()
        keys = self.bitmap.keys()
        keys.sort()
        for k in keys:
            if value & (1 << self.bitmap[k]):
                result.append(k)

        return ', '.join(result)

    def __format__(self, formatspec):
        return format(self.__str__(), formatspec)

    def __getattr__(self, attr):
        maprange = self.maskmap.get(attr)
        if not maprange:
            return obj.NoneObject("Mask {0} not known".format(attr))

        bits = 2 ** maprange[1] - 1
        mask = bits << maprange[0]

        return self.v() & mask

obj.Profile.object_classes['Flags'] = Flags

class Enumeration(obj.NativeType):
    """Enumeration class for handling multiple possible meanings for a single value"""

    def __init__(self, theType = None, offset = 0, vm = None, parent = None,
                 choices = None, target = "unsigned long", **kwargs):
        self.choices = choices or {}
        self.target = target
        self.target_obj = obj.Object(target, offset = offset, vm = vm, parent = parent)
        obj.NativeType.__init__(self, theType, offset, vm, parent, **kwargs)

    def v(self):
        return self.target_obj.v()

    def __str__(self):
        value = self.v()
        if value in self.choices.keys():
            return self.choices[value]
        return 'Unknown choice ' + str(value)

    def __format__(self, formatspec):
        return format(self.__str__(), formatspec)

obj.Profile.object_classes['Enumeration'] = Enumeration


class VOLATILITY_MAGIC(obj.CType):
    """Class representing a VOLATILITY_MAGIC namespace
    
       Needed to ensure that the address space is not verified as valid for constants
    """
    def __init__(self, theType, offset, vm, **kwargs):
        try:
            obj.CType.__init__(self, theType, offset, vm, **kwargs)
        except obj.InvalidOffsetError:
            # The exception will be raised before this point,
            # so we must finish off the CType's __init__ ourselves
            self.__initialized = True

obj.Profile.object_classes['VOLATILITY_MAGIC'] = VOLATILITY_MAGIC

class VolatilityDTB(obj.VolatilityMagic):

    def generate_suggestions(self):
        offset = 0
        while 1:
            data = self.obj_vm.read(offset, constants.SCAN_BLOCKSIZE)
            found = 0
            if not data:
                break

            while 1:
                found = data.find(str(self.obj_parent.DTBSignature), found + 1)
                if found >= 0:
                    # (_type, _size) = unpack('=HH', data[found:found+4])
                    proc = obj.Object("_EPROCESS", offset = offset + found,
                                      vm = self.obj_vm)
                    if 'Idle' in proc.ImageFileName.v():
                        yield proc.Pcb.DirectoryTableBase.v()
                else:
                    break

            offset += len(data)

obj.Profile.object_classes['VolatilityDTB'] = VolatilityDTB



### DEPRECATED FEATURES ###
#
# These are due from removal after version 2.2,
# please do not rely upon them

x86_native_types_32bit = x86_native_types
x86_native_types_64bit = x64_native_types
