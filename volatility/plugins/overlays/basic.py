# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
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

""" This file defines some basic types which might be useful for many
OS's
"""
import struct, socket, datetime

import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.constants as constants
import volatility.plugins.overlays.native_types as native_types
import volatility.utils as utils
import volatility.timefmt as timefmt

class String(obj.BaseObject):
    """Class for dealing with Strings"""
    def __init__(self, theType, offset, vm = None, encoding = 'ascii',
                 length = 1, parent = None, profile = None, **kwargs):

        ## Allow length to be a callable:
        if callable(length):
            length = length(parent)

        self.length = length
        self.encoding = encoding

        ## length must be an integer
        obj.BaseObject.__init__(self, theType, offset, vm, parent = parent, profile = profile, **kwargs)

    def proxied(self, name): #pylint: disable-msg=W0613
        """ Return an object to be proxied """
        return self.__str__()

    def v(self):
        """
        Use zread to help emulate reading null-terminated C
        strings across page boundaries.

        @returns: If all bytes are available, return the full string
        as a raw byte buffer. If the end of the string is in a page
        that isn't available, return as much of the string as possible,
        padded with nulls to the string's length.

        If the string length is 0, vtop() fails, or the physical addr
        of the string is not valid, return NoneObject.

        Note: to get a null terminated string, use the __str__ method.
        """
        result = self.obj_vm.zread(self.obj_offset, self.length)
        if not result:
            return obj.NoneObject("Cannot read string length {0} at {1:#x}".format(self.length, self.obj_offset))
        return result

    def __len__(self):
        """This returns the length of the string"""
        return len(unicode(self))

    def __str__(self):
        """
        This function ensures that we always return a string from the __str__ method.
        Any unusual/unicode characters in the input are replaced with ?.

        Note: this effectively masks the NoneObject alert from .v()
        """
        return unicode(self).encode('ascii', 'replace') or ""

    def __unicode__(self):
        """ This function returns the unicode encoding of the data retrieved by .v()
            Any unusual characters in the input are replaced with \ufffd.
        """
        return self.v().decode(self.encoding, 'replace').split("\x00", 1)[0] or u''

    def __format__(self, formatspec):
        return format(self.__str__(), formatspec)

    def __cmp__(self, other):
        if str(self) == other:
            return 0
        return -1 if str(self) < other else 1

    def __add__(self, other):
        """Set up mappings for concat"""
        return str(self) + other

    def __radd__(self, other):
        """Set up mappings for reverse concat"""
        return other + str(self)

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

class IpAddress(obj.NativeType):
    """Provides proper output for IpAddress objects"""

    def __init__(self, theType, offset, vm, **kwargs):
        obj.NativeType.__init__(self, theType, offset, vm, format_string = "4s", **kwargs)

    def v(self):
        return utils.inet_ntop(socket.AF_INET, obj.NativeType.v(self))

class Ipv6Address(obj.NativeType):
    """Provides proper output for Ipv6Address objects"""
    def __init__(self, theType, offset, vm, **kwargs):
        obj.NativeType.__init__(self, theType, offset, vm, format_string = "16s", **kwargs)

    def v(self):
        return utils.inet_ntop(socket.AF_INET6, obj.NativeType.v(self))

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


class VolatilityDTB(obj.VolatilityMagic):

    def generate_suggestions(self):
        offset = 0
        data = self.obj_vm.zread(offset, constants.SCAN_BLOCKSIZE)
        last_range_start, last_range_size = sorted(self.obj_vm.get_available_addresses())[-1]
        max_offset = last_range_start + last_range_size
        while data:
            found = data.find(str(self.obj_parent.DTBSignature), 0)
            while found >= 0:
                proc = obj.Object("_EPROCESS", offset = offset + found,
                                  vm = self.obj_vm)
                if 'Idle' in proc.ImageFileName.v():
                    yield proc.Pcb.DirectoryTableBase.v()
                found = data.find(str(self.obj_parent.DTBSignature), found + 1)

            offset += len(data)
            if offset >= max_offset:
                break 
            data = self.obj_vm.zread(offset, constants.SCAN_BLOCKSIZE)

class UnixTimeStamp(obj.NativeType):
    """Class for handling Unix Time Stamps"""

    def __init__(self, theType, offset, vm, is_utc = False, **kwargs):
        self.is_utc = is_utc
        obj.NativeType.__init__(self, theType, offset, vm, format_string = "I", **kwargs)

    def v(self):
        return obj.NativeType.v(self)

    def __nonzero__(self):
        return self.v() != 0

    def __str__(self):
        return "{0}".format(self)

    def as_datetime(self):
        try:
            dt = datetime.datetime.utcfromtimestamp(self.v())
            if self.is_utc:
                # Only do dt.replace when dealing with UTC
                dt = dt.replace(tzinfo = timefmt.UTC())
        except ValueError, e:
            return obj.NoneObject("Datetime conversion failure: " + str(e))
        return dt

    def __format__(self, formatspec):
        """Formats the datetime according to the timefmt module"""
        dt = self.as_datetime()
        if dt != None:
            return format(timefmt.display_datetime(dt), formatspec)
        return "-"

class VolatilityMaxAddress(obj.VolatilityMagic):
    """The maximum address of a profile's 
    underlying AS. 

    On x86 this is 0xFFFFFFFF (2 ** 32) - 1
    On x64 this is 0xFFFFFFFFFFFFFFFF (2 ** 64) - 1 

    We use a VolatilityMagic to calculate this 
    based on the size of an address, since that's 
    something we can already rely on being set
    properly for the AS. 
    """

    def generate_suggestions(self):
        yield 2 ** (self.obj_vm.profile.get_obj_size("address") * 8) - 1

class BasicObjectClasses(obj.ProfileModification):

    def modification(self, profile):
        profile.object_classes.update({
            'String': String,
            'Flags': Flags,
            'Enumeration': Enumeration,
            'VOLATILITY_MAGIC': VOLATILITY_MAGIC,
            'VolatilityDTB': VolatilityDTB,
            'UnixTimeStamp': UnixTimeStamp,
            'VolatilityMaxAddress': VolatilityMaxAddress,
            })

        profile.merge_overlay({'VOLATILITY_MAGIC': [None, {
            'MaxAddress': [0x0, ['VolatilityMaxAddress']],
            }]})

### DEPRECATED FEATURES ###
#
# These are due from removal after version 2.2,
# please do not rely upon them

x86_native_types_32bit = native_types.x86_native_types
x86_native_types_64bit = native_types.x64_native_types
