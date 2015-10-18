#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v.0.3.0

import sys
import struct
from datetime import datetime
from functools import partial

verbose = False


def debug(*message):
    """
    TODO(wb): replace with logging
    """
    global verbose
    if verbose:
        print "# [d] %s" % (", ".join(map(str, message)))


def warning(message):
    """
    TODO(wb): replace with logging
    """
    print "# [w] %s" % (message)


def info(message):
    """
    TODO(wb): replace with logging
    """
    print "# [i] %s" % (message)


def error(message):
    """
    TODO(wb): replace with logging
    """
    print "# [e] %s" % (message)
    sys.exit(-1)


def hex_dump(src, start_addr=0):
    """
    see:
    http://code.activestate.com/recipes/142812-hex-dumper/
    @param src A bytestring containing the data to dump.
    @param start_addr An integer representing the start
      address of the data in whatever context it comes from.
    @return A string containing a classic hex dump with 16
      bytes per line.  If start_addr is provided, then the
      data is interpreted as starting at this offset, and
      the offset column is updated accordingly.
    """
    FILTER = ''.join([(len(repr(chr(x))) == 3) and
                        chr(x) or
                        '.' for x in range(256)])
    length = 16
    result = []

    remainder_start_addr = start_addr

    if start_addr % length != 0:
        base_addr = start_addr - (start_addr % length)
        num_spaces = (start_addr % length)
        num_chars = length - (start_addr % length)

        spaces = " ".join(["  " for i in xrange(num_spaces)])
        s = src[0:num_chars]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        printable = s.translate(FILTER)

        result.append("%04X   %s %s   %s%s\n" %
                      (base_addr, spaces, hexa,
                      " " * (num_spaces + 1), printable))

        src = src[num_chars:]
        remainder_start_addr = base_addr + length

    for i in xrange(0, len(src), length):
        s = src[i:i + length]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append("%04X   %-*s   %s\n" %
                         (remainder_start_addr + i, length * 3,
                          hexa, printable))

    return ''.join(result)


class memoize(object):
    """cache the return value of a method

    From http://code.activestate.com/recipes/577452-a-memoize-decorator-for-instance-methods/

    This class is meant to be used as a decorator of methods. The return value
    from a given method invocation will be cached on the instance whose method
    was invoked. All arguments passed to a method decorated with memoize must
    be hashable.

    If a memoized method is invoked directly on its class the result will not
    be cached. Instead the method will be invoked like a static method:
    class Obj(object):
        @memoize
        def add_to(self, arg):
            return self + arg
    Obj.add_to(1) # not enough arguments
    Obj.add_to(1, 2) # returns 3, result is not cached
    """
    def __init__(self, func):
        self.func = func

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self.func
        return partial(self, obj)

    def __call__(self, *args, **kw):
        obj = args[0]
        try:
            cache = obj.__cache
        except AttributeError:
            cache = obj.__cache = {}
        key = (self.func, args[1:], frozenset(kw.items()))
        try:
            res = cache[key]
        except KeyError:
            res = cache[key] = self.func(*args, **kw)
        return res


def align(offset, alignment):
    """
    Return the offset aligned to the nearest greater given alignment
    Arguments:
    - `offset`: An integer
    - `alignment`: An integer
    """
    if offset % alignment == 0:
        return offset
        return offset + (alignment - (offset % alignment))


def dosdate(dosdate, dostime):
    """
    `dosdate`: 2 bytes, little endian.
    `dostime`: 2 bytes, little endian.
    returns: datetime.datetime or datetime.datetime.min on error
    """
    try:
        t  = ord(dosdate[1]) << 8
        t |= ord(dosdate[0])
        day   = t & 0b0000000000011111
        month = (t & 0b0000000111100000) >> 5
        year  = (t & 0b1111111000000000) >> 9
        year += 1980

        t  = ord(dostime[1]) << 8
        t |= ord(dostime[0])
        sec     = t & 0b0000000000011111
        sec    *= 2
        minute  = (t & 0b0000011111100000) >> 5
        hour    = (t & 0b1111100000000000) >> 11

        return datetime.datetime(year, month, day, hour, minute, sec)
    except:
        return datetime.datetime.min


def parse_filetime(qword):
    # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
    try:
        return datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)
    except ValueError:
        return datetime.min


class BinaryParserException(Exception):
    """
    Base Exception class for binary parsing.
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(BinaryParserException, self).__init__()
        self._value = value

    def __repr__(self):
        return "BinaryParserException(%r)" % (self._value)

    def __str__(self):
        return "Binary Parser Exception: %s" % (self._value)


class ParseException(BinaryParserException):
    """
    An exception to be thrown during binary parsing, such as
    when an invalid header is encountered.
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(ParseException, self).__init__(value)

    def __repr__(self):
        return "ParseException(%r)" % (self._value)

    def __str__(self):
        return "Parse Exception(%s)" % (self._value)


class OverrunBufferException(ParseException):
    def __init__(self, readOffs, bufLen):
        tvalue = "read: %s, buffer length: %s" % (hex(readOffs), hex(bufLen))
        super(ParseException, self).__init__(tvalue)

    def __repr__(self):
        return "OverrunBufferException(%r)" % (self._value)

    def __str__(self):
        return "Tried to parse beyond the end of the file (%s)" % \
            (self._value)


class Block(object):
    """
    Base class for structure blocks in binary parsing.
    A block is associated with a offset into a byte-string.
    """
    def __init__(self, buf, offset):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing stuff to parse.
        - `offset`: The offset into the buffer at which the block starts.
        """
        self._buf = buf
        self._offset = offset
        self._implicit_offset = 0
        #print "-- OBJECT: %s" % self.__class__.__name__

    def __repr__(self):
        return "Block(buf=%r, offset=%r)" % (self._buf, self._offset)

    def __unicode__(self):
        return u"BLOCK @ %s." % (hex(self.offset()))

    def __str__(self):
        return str(unicode(self))

    def declare_field(self, type, name, offset=None, length=None):
        """
        Declaratively add fields to this block.
        This method will dynamically add corresponding
          offset and unpacker methods to this block.
        Arguments:
        - `type`: A string. Should be one of the unpack_* types.
        - `name`: A string.
        - `offset`: A number.
        - `length`: (Optional) A number. For (w)strings, length in chars.
        """
        if offset == None:
            offset = self._implicit_offset
        if length == None:

            def no_length_handler():
                f = getattr(self, "unpack_" + type)
                return f(offset)
            setattr(self, name, no_length_handler)
        else:

            def explicit_length_handler():
                f = getattr(self, "unpack_" + type)
                return f(offset, length)
            setattr(self, name, explicit_length_handler)

        setattr(self, "_off_" + name, offset)
        if type == "byte":
            self._implicit_offset = offset + 1
        elif type == "int8":
            self._implicit_offset = offset + 1
        elif type == "word":
            self._implicit_offset = offset + 2
        elif type == "word_be":
            self._implicit_offset = offset + 2
        elif type == "int16":
            self._implicit_offset = offset + 2
        elif type == "dword":
            self._implicit_offset = offset + 4
        elif type == "dword_be":
            self._implicit_offset = offset + 4
        elif type == "int32":
            self._implicit_offset = offset + 4
        elif type == "qword":
            self._implicit_offset = offset + 8
        elif type == "int64":
            self._implicit_offset = offset + 8
        elif type == "float":
            self._implicit_offset = offset + 4
        elif type == "double":
            self._implicit_offset = offset + 8
        elif type == "dosdate":
            self._implicit_offset = offset + 4
        elif type == "filetime":
            self._implicit_offset = offset + 8
        elif type == "systemtime":
            self._implicit_offset = offset + 8
        elif type == "guid":
            self._implicit_offset = offset + 16
        elif type == "binary":
            self._implicit_offset = offset + length
        elif type == "string" and length != None:
            self._implicit_offset = offset + length
        elif type == "wstring" and length != None:
            self._implicit_offset = offset + (2 * length)
        elif "string" in type and length == None:
            raise ParseException("Implicit offset not supported "
                                 "for dynamic length strings")
        else:
            raise ParseException("Implicit offset not supported "
                                 "for type: " + type)

    def current_field_offset(self):
        return self._implicit_offset

    def unpack_byte(self, offset):
        """
        Returns a little-endian unsigned byte from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<B", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int8(self, offset):
        """
        Returns a little-endian signed byte from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<b", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_word(self, offset):
        """
        Returns a little-endian unsigned WORD (2 bytes) from the
          relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<H", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_word_be(self, offset):
        """
        Returns a big-endian unsigned WORD (2 bytes) from the
          relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from(">H", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int16(self, offset):
        """
        Returns a little-endian signed WORD (2 bytes) from the
          relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<h", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def pack_word(self, offset, word):
        """
        Applies the little-endian WORD (2 bytes) to the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `word`: The data to apply.
        """
        o = self._offset + offset
        return struct.pack_into("<H", self._buf, o, word)

    def unpack_dword(self, offset):
        """
        Returns a little-endian DWORD (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<I", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_dword_be(self, offset):
        """
        Returns a big-endian DWORD (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from(">I", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int32(self, offset):
        """
        Returns a little-endian signed integer (4 bytes) from the
          relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<i", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_qword(self, offset):
        """
        Returns a little-endian QWORD (8 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<Q", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int64(self, offset):
        """
        Returns a little-endian signed 64-bit integer (8 bytes) from
          the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<q", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_float(self, offset):
        """
        Returns a single-precision float (4 bytes) from
          the relative offset.  IEEE 754 format.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<f", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_double(self, offset):
        """
        Returns a double-precision float (8 bytes) from
          the relative offset.  IEEE 754 format.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<d", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_binary(self, offset, length=False):
        """
        Returns raw binary data from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the binary blob. If zero, the empty string
            zero length is returned.
        Throws:
        - `OverrunBufferException`
        """
        if not length:
            return ""
        o = self._offset + offset
        try:
            return struct.unpack_from("<%ds" % (length), self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_string(self, offset, length):
        """
        Returns a string from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the string.
        Throws:
        - `OverrunBufferException`
        """
        return self.unpack_binary(offset, length)

    def unpack_wstring(self, offset, length):
        """
        Returns a string from the relative offset with the given length,
        where each character is a wchar (2 bytes)
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the string.
        Throws:
        - `UnicodeDecodeError`
        """
        try:
            return self._buf[self._offset + offset:self._offset + offset + \
                             2 * length].tostring().decode("utf16")
        except AttributeError: # already a 'str' ?
            return self._buf[self._offset + offset:self._offset + offset + \
                             2 * length].decode("utf16")

    def unpack_dosdate(self, offset):
        """
        Returns a datetime from the DOSDATE and DOSTIME starting at
        the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        try:
            o = self._offset + offset
            return dosdate(self._buf[o:o + 2], self._buf[o + 2:o + 4])
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_filetime(self, offset):
        """
        Returns a datetime from the QWORD Windows timestamp starting at
        the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        return parse_filetime(self.unpack_qword(offset))

    def unpack_systemtime(self, offset):
        """
        Returns a datetime from the QWORD Windows SYSTEMTIME timestamp
          starting at the relative offset.
          See http://msdn.microsoft.com/en-us/library/ms724950%28VS.85%29.aspx
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            parts = struct.unpack_from("<WWWWWWWW", self._buf, o)
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))
        return datetime.datetime(parts[0], parts[1],
                                 parts[3],  # skip part 2 (day of week)
                                 parts[4], parts[5],
                                 parts[6], parts[7])

    def unpack_guid(self, offset):
        """
        Returns a string containing a GUID starting at the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset

        try:
            _bin = self._buf[o:o + 16]
        except IndexError:
            raise OverrunBufferException(o, len(self._buf))

        # Yeah, this is ugly
        h = map(ord, _bin)
        return "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x" % \
            (h[3], h[2], h[1], h[0],
             h[5], h[4],
             h[7], h[6],
             h[8], h[9],
             h[10], h[11], h[12], h[13], h[14], h[15])

    def absolute_offset(self, offset):
        """
        Get the absolute offset from an offset relative to this block
        Arguments:
        - `offset`: The relative offset into this block.
        """
        return self._offset + offset

    def offset(self):
        """
        Equivalent to self.absolute_offset(0x0), which is the starting
          offset of this block.
        """
        return self._offset
