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

#pylint: disable-msg=C0111,W0613
import sys
if __name__ == '__main__':
    sys.path.append(".")
    sys.path.append("..")

import re
import cPickle as pickle # pickle implementation must match that in volatility.cache
import struct, copy, operator
import volatility.debug as debug
import volatility.utils as utils

## Curry is now a standard python feature
import functools

Curry = functools.partial

import traceback

def get_bt_string(_e = None):
    return ''.join(traceback.format_stack()[:-3])

class FormatSpec(object):
    def __init__(self, string = '', **kwargs):
        self.fill = ''
        self.align = ''
        self.sign = ''
        self.altform = False
        self.minwidth = -1
        self.precision = -1
        self.formtype = ''

        if string != '':
            self.from_string(string)

        # Ensure we parse the remaining arguments after the string to that they override
        self.from_specs(**kwargs)

    def from_specs(self, fill = None, align = None, sign = None, altform = None, minwidth = None, precision = None, formtype = None):
        ## Allow setting individual elements using kwargs 
        if fill is not None:
            self.fill = fill
        if align is not None:
            self.align = align
        if sign is not None:
            self.sign = sign
        if altform is not None:
            self.altform = altform
        if minwidth is not None:
            self.minwidth = minwidth
        if precision is not None:
            self.precision = precision
        if formtype is not None:
            self.formtype = formtype

    def from_string(self, formatspec):
        # Format specifier regular expression
        regexp = "\A(.[<>=^]|[<>=^])?([-+ ]|\(\))?(#?)(0?)(\d*)(\.\d+)?(.)?\Z"

        match = re.search(regexp, formatspec)

        if match is None:
            raise ValueError("Invalid format specification")

        if match.group(1):
            fillalign = match.group(1)
            if len(fillalign) > 1:
                self.fill = fillalign[0]
                self.align = fillalign[1]
            elif fillalign:
                self.align = fillalign

        if match.group(2):
            self.sign = match.group(2)
        if match.group(3):
            self.altform = len(match.group(3)) > 0
        if len(match.group(4)):
            if self.fill == "":
                self.fill = "0"
                if self.align == "":
                    self.align = "="
        if match.group(5):
            self.minwidth = int(match.group(5))
        if match.group(6):
            self.precision = int(match.group(6)[1:])
        if match.group(7):
            self.formtype = match.group(7)

    def to_string(self):
        formatspec = self.fill + self.align + self.sign
        if self.sign == '(':
            formatspec += ')'
        if self.altform:
            formatspec += '#'
        if self.minwidth >= 0:
            formatspec += str(self.minwidth)
        if self.precision >= 0:
            formatspec += '.' + str(self.precision)
        formatspec += self.formtype

        return formatspec

    def __str__(self):
        return self.to_string()

class NoneObject(object):
    """ A magical object which is like None but swallows bad
    dereferences, __getattribute__, iterators etc to return itself.

    Instantiate with the reason for the error.
    """
    def __init__(self, reason = '', strict = False):
        debug.debug("None object instantiated: " + reason, 2)
        self.reason = reason
        self.strict = strict
        if strict:
            self.bt = get_bt_string()

    def __str__(self):
        ## If we are strict we blow up here
        if self.strict:
            debug.error("{0} n{1}".format(self.reason, self.bt))
            sys.exit(0)
        else:
            debug.warning("{0}".format(self.reason))

        return ""

    def write(self, data):
        """Write procedure only ever returns False"""
        return False

    ## Behave like an empty set
    def __iter__(self):
        return self

    def __len__(self):
        return 0

    def __format__(self, formatspec):
        spec = FormatSpec(string = formatspec, fill = "-", align = ">")
        return format('-', str(spec))

    def next(self):
        raise StopIteration()

    def __getattribute__(self, attr):
        # By returning self for any unknown attribute
        # and ensuring the self is callable, we cover both properties and methods
        # Override NotImplemented functions in object with self
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            return self

    def __bool__(self):
        return False

    def __nonzero__(self):
        return False

    def __eq__(self, other):
        return (other is None)

    def __ne__(self, other):
        return not self.__eq__(other)

    ## Make us subscriptable obj[j]
    def __getitem__(self, item):
        return self

    def __call__(self, *arg, **kwargs):
        return self

    def __int__(self):
        return -1

    # These must be defined explicitly, 
    # due to the way new style objects bypass __getattribute__ for speed
    # See http://docs.python.org/reference/datamodel.html#new-style-special-lookup
    __add__ = __call__
    __sub__ = __call__
    __mul__ = __call__
    __floordiv__ = __call__
    __mod__ = __call__
    __divmod__ = __call__
    __pow__ = __call__
    __lshift__ = __call__
    __rshift__ = __call__
    __and__ = __call__
    __xor__ = __call__
    __or__ = __call__

    __radd__ = __call__
    __rsub__ = __call__
    __rmul__ = __call__
    __rfloordiv__ = __call__
    __rmod__ = __call__
    __rdivmod__ = __call__
    __rpow__ = __call__
    __rlshift__ = __call__
    __rrshift__ = __call__
    __rand__ = __call__
    __rxor__ = __call__
    __ror__ = __call__


class InvalidOffsetError(utils.VolatilityException):
    """Simple placeholder to identify invalid offsets"""
    pass

def Object(theType, offset, vm, name = None, **kwargs):
    """ A function which instantiates the object named in theType (as
    a string) from the type in profile passing optional args of
    kwargs.
    """
    name = name or theType
    offset = int(offset)

    try:
        if theType in vm.profile.types:
            result = vm.profile.types[theType](offset = offset, vm = vm, name = name, **kwargs)
            return result

        if theType in vm.profile.object_classes:
            result = vm.profile.object_classes[theType](theType = theType,
                                                        offset = offset,
                                                        vm = vm,
                                                        name = name,
                                                        **kwargs)
            return result

    except InvalidOffsetError:
        ## If we cant instantiate the object here, we just error out:
        return NoneObject("Invalid Address 0x{0:08X}, instantiating {1}".format(offset, name),
                          strict = vm.profile.strict)

    ## If we get here we have no idea what the type is supposed to be?
    ## This is a serious error.
    debug.warning("Cant find object {0} in profile {1}?".format(theType, vm.profile))

class BaseObject(object):

    # We have **kwargs here, but it's unclear if it's a good idea
    # Benefit is objects will never fail with duff parameters
    # Downside is typos won't show up and be difficult to diagnose
    def __init__(self, theType, offset, vm, native_vm = None, parent = None, name = None, **kwargs):
        self._vol_theType = theType
        self._vol_offset = offset
        self._vol_vm = vm
        self._vol_native_vm = native_vm
        self._vol_parent = parent
        self._vol_name = name

        if not self.obj_vm.is_valid_address(self.obj_offset):
            raise InvalidOffsetError("Invalid Address 0x{0:08X}, instantiating {1}".format(offset, self.obj_name))

    @property
    def obj_vm(self):
        return self._vol_vm

    @property
    def obj_offset(self):
        return self._vol_offset

    @property
    def obj_parent(self):
        return self._vol_parent

    @property
    def obj_name(self):
        return self._vol_name

    @property
    def obj_native_vm(self):
        return self._vol_native_vm or self._vol_vm

    def set_native_vm(self, native_vm):
        """Sets the native_vm """
        self._vol_native_vm = native_vm

    def rebase(self, offset):
        # If it's needed, we should be using the __getstate__ and __setstate__ functions
        raise DeprecationWarning("The rebase function has been deprecated and will be removed in future versions")

    def proxied(self, attr):
        return None

    def newattr(self, attr, value):
        """Sets a new attribute after the object has been created"""
        return BaseObject.__setattr__(self, attr, value)

    def write(self, value):
        """Function for writing the object back to disk"""
        pass

    def __getattr__(self, attr):
        """ This is only useful for proper methods (not ones that
        start with __ )
        """
        ## Search for the attribute of the proxied object
        proxied = self.proxied(attr)
        # Don't do a __nonzero__ check on proxied or things like '' will fail
        if proxied is None:
            raise AttributeError("Unable to resolve attribute {0} on {1}".format(attr, self.obj_name))

        return getattr(proxied, attr)

    def __setattr__(self, attr, value):
        try:
            object.__setattr__(self, attr, value)
        except AttributeError:
            pass

    def __nonzero__(self):
        """ This method is called when we test the truth value of an
        Object. In volatility we consider an object to have True truth
        value only when its a valid object. Its possible for example
        to have a Pointer object which is not valid - this will have a
        truth value of False.

        You should be testing for validity like this:
        if X:
           # object is valid

        Do not test for validity like this:

        if int(X) == 0:

        or if X is None: .....

        the later form is not going to work when X is a NoneObject. 
        """
        result = self.obj_vm.is_valid_address(self.obj_offset)
        return result

    def __eq__(self, other):
        return self.v() == other or ((self.__class__ == other.__class__) and
                                     (self.obj_offset == other.obj_offset) and (self.obj_vm == other.obj_vm))

    def __hash__(self):
        # This should include the critical components of self.obj_vm
        return hash(self.obj_name) ^ hash(self.obj_offset)

    def m(self, memname):
        raise AttributeError("No member {0}".format(memname))

    def is_valid(self):
        return self.obj_vm.is_valid_address(self.obj_offset)

    def dereference(self):
        return NoneObject("Can't dereference {0}".format(self.obj_name), self.obj_vm.profile.strict)

    def dereference_as(self, derefType, **kwargs):
        # Make sure we use self.obj_native_vm to automatically
        # dereference from the highest available VM
        if self.obj_native_vm.is_valid_address(self.v()):
            return Object(derefType, self.v(), self.obj_native_vm, parent = self, **kwargs)
        else:
            return NoneObject("Invalid offset {0} for dereferencing {1} as {2}".format(self.v(), self.obj_name, derefType))

    def cast(self, castString):
        return Object(castString, self.obj_offset, self.obj_vm)

    def v(self):
        """ Do the actual reading and decoding of this member
        """
        return NoneObject("No value for {0}".format(self.obj_name), self.obj_vm.profile.strict)

    def __format__(self, formatspec):
        return format(self.v(), formatspec)

    def __str__(self):
        return str(self.v())

    def __repr__(self):
        return "[{0} {1}] @ 0x{2:08X}".format(self.__class__.__name__, self.obj_name or '',
                                              self.obj_offset)

    def d(self):
        """Display diagnostic information"""
        return self.__repr__()

    def __getstate__(self):
        """ This controls how we pickle and unpickle the objects """
        try:
            thetype = self._vol_theType.__name__
        except AttributeError:
            thetype = self._vol_theType

        # Note: we lose the parent attribute here
        result = dict(offset = self.obj_offset,
                      name = self.obj_name,
                      vm = self.obj_vm,
                      native_vm = self.obj_native_vm,
                      theType = thetype)

        ## Introspect the kwargs for the constructor and store in the dict
        try:
            for arg in self.__init__.func_code.co_varnames:
                if (arg not in result and
                    arg not in "self parent profile args".split()):
                    result[arg] = self.__dict__[arg]
        except KeyError:
            debug.post_mortem()
            raise pickle.PicklingError("Object {0} at 0x{1:08x} cannot be cached because of missing attribute {2}".format(self.obj_name, self.obj_offset, arg))

        return result

    def __setstate__(self, state):
        ## What we want to do here is to instantiate a new object and then copy it into ourselves
        #new_object = Object(state['theType'], state['offset'], state['vm'], name = state['name'])
        new_object = Object(**state)
        if not new_object:
            raise pickle.UnpicklingError("Object {0} at 0x{1:08x} invalid".format(state['name'], state['offset']))

        ## (Scudette) Im not sure how much of a hack this is - we
        ## basically take over all the new object's members. This is
        ## needed because __setstate__ can not return a new object,
        ## but must update the current object instead. I'm sure ikelos
        ## will object!!! I am open to suggestions ...
        self.__dict__ = new_object.__dict__

def CreateMixIn(mixin):
    def make_method(name):
        def method(self, *args, **kw):
            proxied = self.proxied(name)
            try:
                ## Try to coerce the other in case its also a proxied
                ## class
                args = list(args)
                args[0] = args[0].proxied(name)
            except (AttributeError, IndexError):
                pass

            try:
                method = getattr(operator, name)
                args = [proxied] + args
            except AttributeError:
                method = getattr(proxied, name)

            return method(*args, **kw)

        return method

    for name in mixin._specials:
        setattr(mixin, name, make_method(name))

class NumericProxyMixIn(object):
    """ This MixIn implements the numeric protocol """
    _specials = [
        ## Number protocols
        '__add__', '__sub__', '__mul__', '__floordiv__', '__mod__', '__divmod__',
        '__pow__', '__lshift__', '__rshift__', '__and__', '__xor__', '__or__', '__div__',
        '__truediv__', '__radd__', '__rsub__', '__rmul__', '__rdiv__', '__rtruediv__',
        '__rfloordiv__', '__rmod__', '__rdivmod__', '__rpow__', '__rlshift__',
        '__rrshift__', '__rand__', '__rxor__', '__ror__', '__neg__', '__pos__',
        '__abs__', '__invert__', '__int__', '__long__', '__float__', '__oct__',
        '__hex__',

        ## Comparisons
        '__lt__', '__le__', '__eq__', '__ne__', '__ge__', '__gt__', '__index__',

        ## Formatting
        '__format__',
        ]


CreateMixIn(NumericProxyMixIn)

class NativeType(BaseObject, NumericProxyMixIn):
    def __init__(self, theType, offset, vm, format_string = None, **kwargs):
        BaseObject.__init__(self, theType, offset, vm, **kwargs)
        NumericProxyMixIn.__init__(self)
        self.format_string = format_string

    def write(self, data):
        """Writes the data back into the address space"""
        output = struct.pack(self.format_string, data)
        return self.obj_vm.write(self.obj_offset, output)

    def proxied(self, attr):
        return self.v()

    def size(self):
        return struct.calcsize(self.format_string)

    def v(self):
        data = self.obj_vm.read(self.obj_offset, self.size())
        if not data:
            return NoneObject("Unable to read {0} bytes from {1}".format(self.size(), self.obj_offset))

        (val,) = struct.unpack(self.format_string, data)

        return val

    def cdecl(self):
        return self.obj_name

    def __repr__(self):
        return " [{0}]: {1}".format(self._vol_theType, self.v())

    def d(self):
        return " [{0} {1} | {2}]: {3}".format(self.__class__.__name__, self.obj_name or '',
                                              self._vol_theType, self.v())

class BitField(NativeType):
    """ A class splitting an integer into a bunch of bit. """
    def __init__(self, theType, offset, vm, start_bit = 0, end_bit = 32, native_type = None, **kwargs):
        # Defaults to profile-endian address, but can be overridden by native_type
        format_string = vm.profile.native_types.get(native_type, vm.profile.native_types['address'])[1]
        NativeType.__init__(self, theType, offset, vm, format_string = format_string, **kwargs)
        self.start_bit = start_bit
        self.end_bit = end_bit
        self.native_type = native_type # Store this for proper caching

    def v(self):
        i = NativeType.v(self)
        return (i & ((1 << self.end_bit) - 1)) >> self.start_bit

    def write(self, data):
        data = data << self.start_bit
        return NativeType.write(self, data)


class Pointer(NativeType):
    def __init__(self, theType, offset, vm, target = None, **kwargs):
        # Default to profile-endian address
        # We don't allow native_type overriding for pointers since we can't dereference invalid pointers anyway
        # You can define a POINTER_64 in 32-bit windows, it becomes a signed pointer for use with special pointers like -1.
        # However, in that case it's unlikely to dereference properly either
        # We can always change this later if it becomes necessary to handle such unusual circumstances
        NativeType.__init__(self, theType, offset, vm, format_string = vm.profile.native_types['address'][1], **kwargs)

        if theType:
            self.target = Curry(Object, theType)
        else:
            self.target = target

    def __getstate__(self):
        ## This one is too complicated to pickle right now
        raise pickle.PicklingError("Pointer objects do not support caching")

    def is_valid(self):
        """ Returns if what we are pointing to is valid """
        return self.obj_vm.is_valid_address(self.v())

    def dereference(self):
        offset = self.v()
        if self.obj_native_vm.is_valid_address(offset):
            # Make sure we use self.obj_native_vm to automatically
            # dereference from the highest available VM
            result = self.target(offset = offset,
                                 vm = self.obj_native_vm,
                                 parent = self.obj_parent,
                                 name = self.obj_name)
            return result
        else:
            return NoneObject("Pointer {0} invalid".format(self.obj_name), self.obj_vm.profile.strict)

    def cdecl(self):
        return "Pointer {0}".format(self.v())

    def __nonzero__(self):
        return bool(self.is_valid())

    def __repr__(self):
        target = self.dereference()
        return "<{0} pointer to [0x{1:08X}]>".format(target.__class__.__name__, self.v())

    def d(self):
        target = self.dereference()
        return "<{0} {1} pointer to [0x{2:08X}]>".format(target.__class__.__name__, self.obj_name or '', self.v())

    def __getattribute__(self, attr):
        try:
            return super(Pointer, self).__getattribute__(attr)
        except AttributeError:
            ## We just dereference ourself
            result = self.dereference()

            #if isinstance(result, CType):
            #    return result.m(attr)
            return result.__getattribute__(attr)

class Void(NativeType):
    def __init__(self, theType, offset, vm, **kwargs):
        # Default to profile-endian unsigned long
        # This should never need to be overridden, but can be by changing the 'Void' value in a profile's object_classes
        format_string = vm.profile.native_types['unsigned long'][1]
        NativeType.__init__(self, theType, offset, vm, format_string = format_string, **kwargs)

    def cdecl(self):
        return "0x{0:08X}".format(self.v())

    def __repr__(self):
        return "Void (0x{0:08X})".format(self.v())

    def d(self):
        return "Void[{0} {1}] (0x{2:08X})".format(self.__class__.__name__, self.obj_name or '', self.v())

    def __nonzero__(self):
        return bool(self.dereference())

class Array(BaseObject):
    """ An array of objects of the same size """
    def __init__(self, theType, offset, vm, parent = None,
                 count = 1, targetType = None, target = None, name = None, **kwargs):
        ## Instantiate the first object on the offset:
        BaseObject.__init__(self, theType, offset, vm,
                            parent = parent, name = name, **kwargs)

        if callable(count):
            count = count(parent)

        self.count = int(count)

        self.original_offset = offset
        if targetType:
            self.target = Curry(Object, targetType)
        else:
            self.target = target

        self.current = self.target(offset = offset, vm = vm, parent = self, name = name)
        if self.current.size() == 0:
            ## It is an error to have a zero sized element
            debug.debug("Array with 0 sized members???", level = 10)
            debug.b()

    def __getstate__(self):
        ## This one is too complicated to pickle right now
        raise pickle.PicklingError("Array objects do not support caching")

    def size(self):
        return self.count * self.current.size()

    def __iter__(self):
        ## This method is better than the __iter__/next method as it
        ## is reentrant
        for position in range(0, self.count):

            ## We don't want to stop on a NoneObject.  Its
            ## entirely possible that this array contains a bunch of
            ## pointers and some of them may not be valid (or paged
            ## in). This should not stop us though we just return the
            ## invalid pointers to our callers.  It's up to the callers
            ## to do what they want with the array.
            if (self.current == None):
                return

            yield self[position]

    def __repr__(self):
        result = [ x.__str__() for x in self ]
        return "<Array {0}>".format(",".join(result))

    def d(self):
        result = [ x.__str__() for x in self ]
        return "<Array[{0} {1}] {2}>".format(self.__class__.__name__, self.obj_name or '', ",".join(result))

    def __eq__(self, other):
        if self.count != len(other):
            return False

        for i in range(self.count):
            if not self[i] == other[i]:
                return False

        return True

    def __getitem__(self, pos):
        ## Check for slice object
        if isinstance(pos, slice):
            start, stop, step = pos.indices(self.count)
            return [self[i] for i in xrange(start, stop, step)]

        ## Check if the offset is valid
        offset = self.original_offset + pos * self.current.size()

        if pos <= self.count and self.obj_vm.is_valid_address(offset):
            # Ensure both the true VM and offsetlayer are copied across
            return self.target(offset = offset,
                               vm = self.obj_vm,
                               native_vm = self.obj_native_vm,
                               parent = self,
                               name = "{0} {1}".format(self.obj_name, pos))
        else:
            return NoneObject("Array {0} invalid member {1}".format(self.obj_name, pos),
                              self.obj_vm.profile.strict)

class CType(BaseObject):
    """ A CType is an object which represents a c struct """
    def __init__(self, theType, offset, vm, name = None, members = None, struct_size = 0, **kwargs):
        """ This must be instantiated with a dict of members. The keys
        are the offsets, the values are Curried Object classes that
        will be instantiated when accessed.
        """
        if not members:
            # Warn rather than raise an error, since some types (_HARDWARE_PTE, for example) are generated without members
            debug.debug("No members specified for CType {0} named {1}".format(theType, name), level = 2)
            members = {}

        self.members = members
        self.struct_size = struct_size
        BaseObject.__init__(self, theType, offset, vm, name = name, **kwargs)
        self.__initialized = True

    def size(self):
        return self.struct_size

    def __repr__(self):
        return "[{0} {1}] @ 0x{2:08X}".format(self.__class__.__name__, self.obj_name or '',
                                     self.obj_offset)
    def d(self):
        result = self.__repr__() + "\n"
        for k in self.members.keys():
            result += " {0} -\n {1}\n".format(k, self.m(k))

        return result

    def v(self):
        """ When a struct is evaluated we just return our offset.
        """
        return self.obj_offset

    def m(self, attr):
        if attr in self.members:
            offset, cls = self.members[attr]
        elif attr.find('__') > 0 and attr[attr.find('__'):] in self.members:
            offset, cls = self.members[attr[attr.find('__'):]]
        else:
            ## hmm - tough choice - should we raise or should we not
            #return NoneObject("Struct {0} has no member {1}".format(self.obj_name, attr))
            raise AttributeError("Struct {0} has no member {1}".format(self.obj_name, attr))

        if callable(offset):
            ## If offset is specified as a callable its an absolute
            ## offset
            offset = int(offset(self))
        else:
            ## Otherwise its relative to the start of our struct
            offset = int(offset) + int(self.obj_offset)

        result = cls(offset = offset, vm = self.obj_vm, parent = self, name = attr, native_vm = self.obj_native_vm)

        return result

    def __getattribute__(self, attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            pass

        return self.m(attr)

    def __setattr__(self, attr, value):
        """Change underlying members"""
        # Special magic to allow initialization
        if not self.__dict__.has_key('_CType__initialized'):  # this test allows attributes to be set in the __init__ method
            return BaseObject.__setattr__(self, attr, value)
        elif self.__dict__.has_key(attr):       # any normal attributes are handled normally
            return BaseObject.__setattr__(self, attr, value)
        else:
            obj = self.m(attr)
            if not obj.write(value):
                raise ValueError("Error writing value to member " + attr)
        # If you hit this, consider using obj.newattr('attr', value)
        raise ValueError("Attribute " + attr + " was set after object initialization")

class VolatilityMagic(BaseObject):
    """Class to contain Volatility Magic value"""

    def __init__(self, theType, offset, vm, value = None, configname = None, **kwargs):
        try:
            BaseObject.__init__(self, theType, offset, vm, **kwargs)
        except InvalidOffsetError:
            pass
        # If we've been given a configname override,
        # then override the value with the one from the config
        self.configname = configname
        if self.configname:
            configval = getattr(self.obj_vm.get_config(), self.configname)
            # Check the configvalue is actually set to something
            if configval:
                value = configval
        self.value = value

    def v(self):
        # We explicitly want to check for None,
        # in case the user wants a value 
        # that gives not self.value = True
        if self.value is None:
            return self.get_best_suggestion()
        else:
            return self.value

    def __str__(self):
        return self.v()

    def get_suggestions(self):
        """Returns a list of possible suggestions for the value
        
           These should be returned in order of likelihood, 
           since the first one will be taken as the best suggestion
           
           This is also to avoid a complete scan of the memory address space,
           since 
        """
        if self.value:
            yield self.value
        for x in self.generate_suggestions():
            yield x

    def generate_suggestions(self):
        raise StopIteration("No suggestions available")

    def get_best_suggestion(self):
        """Returns the best suggestion for a list of possible suggestsions"""
        for val in self.get_suggestions():
            return val
        else:
            return NoneObject("No suggestions available")

def VolMagic(vm):
    """Convenience function to save people typing out an actual obj.Object call"""
    return Object("VOLATILITY_MAGIC", 0x0, vm = vm)

## Profiles are the interface for creating/interpreting
## objects

class Profile(object):
    """ A profile is a collection of types relating to a certain
    system. We parse the abstract_types and join them with
    native_types to make everything work together.
    """
    _md_os = 'undefined'
    _md_major = 0
    _md_minor = 0
    _md_build = 0
    _md_memory_model = '32bit'
    native_types = {}
    abstract_types = {}
    overlay = {}
    # We initially populate this with objects in this module that will be used everywhere
    object_classes = {'BitField': BitField,
                      'Pointer':Pointer,
                      'Void':Void,
                      'Array':Array,
                      'CType':CType,
                      'VolatilityMagic':VolatilityMagic}

    def __init__(self, strict = False):
        self.types = {}
        self.typeDict = {}
        self.overlayDict = {}
        self.strict = strict

        # Ensure VOLATILITY_MAGIC is always present in every profile
        # That way, we can still autogenerate types, and put VOLATILITY_MAGIC in overlays
        # Otherwise the overlay won't have anything to, well, over lay.
        if 'VOLATILITY_MAGIC' not in self.abstract_types:
            self.abstract_types['VOLATILITY_MAGIC'] = [0x0, {}]

        self.add_types(self.abstract_types, self.overlay)

    @utils.classproperty
    @classmethod
    def metadata(cls):
        prefix = '_md_'
        result = {}
        for i in dir(cls):
            if i.startswith(prefix):
                result[i[len(prefix):]] = getattr(cls, i)
        return result

    def has_type(self, theType):
        return theType in self.object_classes or theType in self.types

    def add_types(self, abstract_types, overlay = None):
        overlay = overlay or {}

        ## we merge the abstract_types with self.typeDict and then recompile
        ## the whole thing again. This is essential because
        ## definitions may have changed as a result of this call, and
        ## we store curried objects (which might keep their previous
        ## definitions).
        for k, v in abstract_types.items():
            original = self.typeDict.get(k, [0, {}])
            original[1].update(v[1])
            if v[0]:
                original[0] = v[0]
            self.typeDict[k] = original

        for k, v in overlay.items():
            original = self.overlayDict.get(k, [None, {}])
            original[1].update(v[1])
            if v[0]:
                original[0] = v[0]

            self.overlayDict[k] = original

        # Load the native types
        self.types = {}
        for nt, value in self.native_types.items():
            if type(value) == list:
                self.types[nt] = Curry(NativeType, nt, format_string = value[1])

        for name in self.typeDict.keys():
            ## We need to protect our virgin overlay dict here - since
            ## the following functions modify it, we need to make a
            ## deep copy:
            self.types[name] = self.convert_members(
                name, self.typeDict, copy.deepcopy(self.overlayDict))

    def list_to_type(self, name, typeList, typeDict = None):
        """ Parses a specification list and returns a VType object.

        This function is a bit complex because we support lots of
        different list types for backwards compatibility.
        """
        ## This supports plugin memory objects:
        try:
            kwargs = typeList[1]

            if type(kwargs) == dict:
                ## We have a list of the form [ ClassName, dict(.. args ..) ]
                return Curry(Object, theType = typeList[0], name = name, **kwargs)
        except (TypeError, IndexError), _e:
            pass

        ## This is of the form [ 'void' ]
        if typeList[0] == 'void':
            return Curry(Void, Void, name = name)

        ## This is of the form [ 'pointer' , [ 'foobar' ]]
        if typeList[0] == 'pointer':
            try:
                target = typeList[1]
            except IndexError:
                raise RuntimeError("Syntax Error in pointer type defintion for name {0}".format(name))

            return Curry(Pointer, None,
                         name = name,
                         target = self.list_to_type(name, target, typeDict))

        ## This is an array: [ 'array', count, ['foobar'] ]
        if typeList[0] == 'array':
            return Curry(Array, None,
                         name = name, count = typeList[1],
                         target = self.list_to_type(name, typeList[2], typeDict))

        ## This is a list which refers to a type which is already defined
        if typeList[0] in self.types:
            return Curry(self.types[typeList[0]], name = name)

        ## Does it refer to a type which will be defined in future? in
        ## this case we just curry the Object function to provide
        ## it on demand. This allows us to define structures
        ## recursively.
        ##if typeList[0] in typeDict:
        if 1:
            try:
                tlargs = typeList[1]
            except IndexError:
                tlargs = {}

            obj_name = typeList[0]
            if type(tlargs) == dict:
                return Curry(Object, obj_name, name = name, **tlargs)

        ## If we get here we have no idea what this list is
        #raise RuntimeError("Error in parsing list {0}".format(typeList))
        debug.warning("Unable to find a type for {0}, assuming int".format(typeList[0]))
        return Curry(self.types['int'], name = name)

    def _get_dummy_obj(self, name):
        class dummy(object):
            profile = self
            name = 'dummy'
            def is_valid_address(self, _offset):
                return True
        tmp = self.types[name](offset = 0, name = name, vm = dummy(), parent = None)
        return tmp

    def get_obj_offset(self, name, member):
        """ Returns a members offset within the struct """
        tmp = self._get_dummy_obj(name)
        offset, _cls = tmp.members[member]

        return offset

    def get_obj_size(self, name):
        """Returns the size of a struct"""
        tmp = self._get_dummy_obj(name)
        return tmp.size()

    def obj_has_member(self, name, member):
        """Returns whether an object has a certain member"""
        tmp = self._get_dummy_obj(name)
        return hasattr(tmp, member)

    def apply_overlay(self, type_member, overlay):
        """ Update the overlay with the missing information from type.

        Basically if overlay has None in any slot it gets applied from vtype.
        """
        if not overlay:
            return type_member

        if type(type_member) == dict:
            for k, v in type_member.items():
                if k not in overlay:
                    overlay[k] = v
                else:
                    overlay[k] = self.apply_overlay(v, overlay[k])

        elif type(overlay) == list:
            if len(overlay) != len(type_member):
                return overlay

            for i in range(len(overlay)):
                if overlay[i] == None:
                    overlay[i] = type_member[i]
                else:
                    overlay[i] = self.apply_overlay(type_member[i], overlay[i])

        return overlay

    def convert_members(self, cname, typeDict, overlay):
        """ Convert the member named by cname from the c description
        provided by typeDict into a list of members that can be used
        for later parsing.

        cname is the name of the struct.
        
        We expect typeDict[cname] to be a list of the following format

        [ Size of struct, members_dict ]

        members_dict is a dict of all members (fields) in this
        struct. The key is the member name, and the value is a list of
        this form:

        [ offset_from_start_of_struct, specification_list ]

        The specification list has the form specified by self.list_to_type() above.

        We return a list of CTypeMember objects. 
        """
        ctype = self.apply_overlay(typeDict[cname], overlay.get(cname))
        members = {}
        size = ctype[0]
        for k, v in ctype[1].items():
            if v[0] == None:
                debug.warning("{0} has no offset in object {1}. Check that vtypes has a concrete definition for it.".format(k, cname))
            members[k] = (v[0], self.list_to_type(k, v[1], typeDict))

        ## Allow the plugins to over ride the class constructor here
        if self.object_classes and cname in self.object_classes:
            cls = self.object_classes[cname]
        else:
            cls = CType

        return Curry(cls, cname, members = members, struct_size = size)
