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
@author:       Jared Smith, Matthew Veca
@license:      GNU General Public License 2.0
@contact:      jared@jaredsmith.io, mattveca@gmail.com
@organization: Volatility Foundation
"""


import volatility
import volatility.conf as conf
import volatility.plugins.common as common
import volatility.utils as utils
import os, subprocess, ntpath
import string
import sys
import re
import binascii
import mmap
import struct
import itertools
import base64
import hashlib
import json
import logging
import traceback
from lxml import etree
from functools import wraps, partial
from datetime import datetime
from xml.sax.saxutils import escape as xml_sax_escape

logger = logging.getLogger("default")


##################################
#   Recovery Utils
##################################

def to_lxml(record_xml):
    """
    Convert an XML string to an Etree element.

    @type record_xml: str
    @rtype: etree.Element
    """
    if "<?xml" not in record_xml:
        return etree.fromstring(
            "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" %
            record_xml)
    else:
        return etree.fromstring(record_xml)


def get_child(node, tag,
              ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    """
    Given an Etree element, get the first child node with the given tag.

    @type node: etree.Element
    @type tag: str
    @type ns: str
    @rtype: etree.Element or None
    """
    return node.find("%s%s" % (ns, tag))


def get_eid(record_xml):
    """
    Given EVTX record XML, return the EID of the record.

    @type record_xml: str
    @rtype: str
    """
    return get_child(get_child(to_lxml(record_xml), "System"), "EventID").text


class Mmap(object):
    """
    Convenience class for opening a read-only memory map for a file path.
    """
    def __init__(self, filename):
        super(Mmap, self).__init__()
        self._filename = filename
        self._f = None
        self._mmap = None

    def __enter__(self):
        self._f = open(self._filename, "rb")
        self._mmap = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        return self._mmap

    def __exit__(self, type, value, traceback):
        self._mmap.close()
        self._f.close()


def exists(fn, iterable):
    """
    Return True if one item in the sequence satisfies the function.
    """
    for i in iterable:
        if fn(i):
            return True
    return False


########################
#   State
########################

CURRENT_VERSION = 1
GENERATOR = "recover-evtx"

def touch(path):
    open(path, 'a').close()


class IncompatibleVersionException(Exception):
    def __init__(self, msg):
        super(IncompatibleVersionException, self).__init__()
        self._msg = msg

    def __str__(self):
        return "IncompatibleVersionException(%s)" % self._msg

class IncompatibleInputFileException(Exception):
    def __init__(self, msg):
        super(IncompatibleInputFileException, self).__init__()
        self._msg = msg

    def __str__(self):
        return "IncompatibleInputFileException(%s)" % self._msg


class State(object):
    """
    Class that loads and saves state to a persistent file.
    """
    def __init__(self, filename):
        self._filename = filename
        self._state = {}

    def __enter__(self):
        if not os.path.exists(self._filename):
            logger.debug("Creating state file: %s", self._filename)
            touch(self._filename)
        else:
            logger.debug("Using existing state file: %s", self._filename)

        with open(self._filename, "rb") as f:
            self._state = json.loads(f.read() or "{}")

        if self._get_version() != CURRENT_VERSION and self._get_version() != "":
            raise IncompatibleVersionException("Version %d expected, got %d" %
                                               (CURRENT_VERSION, self._get_version()))

        self.test_input_file(self._filename)

        self._set_version(CURRENT_VERSION)
        if self._get_generator() == "":
            self._set_generator(GENERATOR)
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        with open(self._filename, "wb") as f:
            f.write(json.dumps(self._state, sort_keys=True,
                               indent=4, separators=(',', ': ')))
        if exc_value:
            logging.warn("Flushing the existing state file due to exception.")
            traceback.print_exception(exc_type, exc_value, exc_traceback)
            return False

    def _set_version(self, version):
        self._state["version"] = version

    def _get_version(self):
        return self._state.get("version", "")

    def _set_generator(self, generator):
        self._state["generator"] = generator

    def _get_generator(self):
        return self._state.get("generator", "")

    def _set_size(self, size):
        meta = self._state.get("metadata", {})
        meta["size"] = size
        self._state["metadata"] = meta

    def _get_size(self):
        meta = self._state.get("metadata", None)
        if meta is None:
            return 0
        return meta.get("size", 0)

    def _set_hash(self, hash_):
        meta = self._state.get("metadata", {})
        meta["hash"] = hash_
        self._state["metadata"] = meta

    def _get_hash(self):
        meta = self._state.get("metadata", None)
        if meta is None:
            return ""
        return meta.get("hash", "")

    def set_input_file(self, input_path):
        self._set_size(os.stat(input_path).st_size)
        m = hashlib.md5()
        with open(input_path, "rb") as f:
            m.update(f.read(0x100000))
        self._set_hash(m.hexdigest())

    def test_input_file(self, input_path):
        """
        Raises IncompatibleInputFileException if the file metadata for the input file
          is not consistent with metadata stored from past runs in the state file.

        @raises IncompatibleInputFileException
        @type input_path: str
        @param input_path: The path to the input file
        @rtype: True
        """
        size = os.stat(input_path).st_size
        m = hashlib.md5()
        with open(input_path, "rb") as f:
            m.update(f.read(0x100000))
        hash_ = m.hexdigest()

        if self._get_size() != 0 and self._get_size != size:
            raise IncompatibleInputFileException("File size: %d, expected %d" % (size, self._get_size()))

        if self._get_hash() != "" and self._get_hash() != hash_:
            raise IncompatibleInputFileException("File hash: %s, expected %s" % (hash_, self._get_hash()))

        return True

    def _add_list_entry(self, list_name, value):
        """
        Append a value to a top level list, creating it if necessary.
        Commits the updated value.
        """
        l = self._state.get(list_name, [])
        l.append(value)
        self._state[list_name] = l

    def add_valid_chunk_offset(self, offset):
        """
        @type offset: int
        """
        self._add_list_entry("valid_chunk_offsets", offset)

    def get_valid_chunk_offsets(self):
        """
        Do not modify the returned list.

        @rtype: list of int
        """
        return self._state.get("valid_chunk_offsets", [])

    def add_potential_record_offset(self, offset):
        """
        @type offset: int
        """
        self._add_list_entry("potential_record_offsets", offset)

    def get_potential_record_offsets(self):
        """
        Do not modify the returned list.

        @rtype: list of int
        """
        return self._state.get("potential_record_offsets", [])

    def add_valid_record(self, offset, eid, xml):
        """
        @type offset: int
        @type eid: int
        @type xml: str
        """
        self._add_list_entry("valid_records", {
            "offset": offset,
            "eid": eid,
            "xml": xml,
        })

    def get_valid_records(self):
        """
        Do not modify the returned list.

        @rtype: list of {}
        @return: List of dicts with the following fields:
          offset: int
          eid: int
          xml: str
        """
        return self._state.get("valid_records", [])

    def add_lost_record(self, offset, timestamp, record_num, substitutions):
        """
        @type offset: int
        @type timestamp: datetime.datetime
        @param timestamp: timezone should be UTC
        @type record_num: int
        @type substitutions: list of (str, str)
        """
        # need to fix up timestamps since they are not JSON serializable
        timestamp_types = set([17, 18])
        if exists(lambda s: s[0] in timestamp_types, substitutions):
            new_subs = []
            for sub in substitutions:
                if sub[0] in timestamp_types:
                    new_subs.append((sub[0], sub[1].isoformat("T") + "Z"))
                else:
                    new_subs.append(sub)
            substitutions = new_subs

        self._add_list_entry("lost_records", {
            "offset": offset,
            "timestamp": timestamp.isoformat("T") + "Z",
            "record_num": record_num,
            "substitutions": substitutions
        })

    def get_lost_records(self):
        """
        Do not modify the returned list.

        @rtype: list of {}
        @return: List of dicts with the following fields:
          offset: int
          timestamp: str
          record_num: int
          substitutions: tuple of:
            type: str
            value: str
        """
        return self._state.get("lost_records", [])

    def add_reconstructed_record(self, offset, eid, xml):
        self._add_list_entry("reconstructed_records", {
            "offset": offset,
            "eid": eid,
            "xml": xml
        })

    def get_reconstructed_records(self):
        """
        Do not modify the returned list.
        """
        return self._state.get("reconstructed_records", [])

    def add_unreconstructed_record(self, offset, substitutions, reason):
        self._add_list_entry("unreconstructed_records", {
            "offset": offset,
            "substitutions": substitutions,
            "reason": reason
        })

    def get_unreconstructed_records(self):
        """
        Do not modify the returned list.
        """
        return self._state.get("unreconstructed_records", [])


########################
#   Template Database
########################

class TemplateEIDConflictError(Exception):
    def __init__(self, value):
        super(TemplateEIDConflictError, self).__init__(value)


class TemplateNotFoundError(Exception):
    def __init__(self, value):
        super(TemplateNotFoundError, self).__init__(value)


class Template(object):
    substitition_re = re.compile("\[(Conditional|Normal) Substitution\(index=(\d+), type=(\d+)\)\]")

    def __init__(self, eid, xml):
        self._eid = eid
        self._xml = xml

        self._cached_placeholders = None
        self._cached_id = None

    def get_xml(self):
        return self._xml

    def get_eid(self):
        return self._eid

    def get_id(self):
        """
        @rtype: str
        @return: A string that can be parsed into constraints describing what
          types of subsitutions this template can accept.
          Short example: 1100-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]
        """
        if self._cached_id is not None:
            return self._cached_id
        ret = ["%s" % self._eid]
        for index, type_, mode in self._get_placeholders():
            if mode:
                mode_str = "c"
            else:
                mode_str = "n"
            ret.append("[%s|%s|%s]" % (index, type_, mode_str))
        self._cached_id = "-".join(ret)
        return self._cached_id

    def _get_placeholders(self):
        """
        Get descriptors for each of the substitutions required by this
          template.

        Tuple schema: (index, type, is_conditional)

        @rtype: list of (int, int, boolean)
        """
        if self._cached_placeholders is not None:
            return self._cached_placeholders
        ret = []
        for mode, index, type_ in Template.substitition_re.findall(self._xml):
            ret.append((int(index), int(type_), mode == "Conditional"))
        self._cached_placeholders = sorted(ret, key=lambda p: p[0])
        return self._cached_placeholders

    def match_substitutions(self, substitutions):
        """
        Checks to see if the provided set of substitutions match the
          placeholder values required by this template.

        Note, this is only a best guess.  The number of substitutions
          *may* be greater than the number of available slots. So we
          must only check the slot and substitution types.



        @type substitutions: list of (int, str)
        @param substitutions: Tuple schema (type, value)
        @rtype: boolean
        """
        logger = logging.getLogger("match_substitutions")
        placeholders = self._get_placeholders()
        logger.debug("Substitutions: %s", str(substitutions))
        logger.debug("Constraints: %s", str(placeholders))
        if len(placeholders) > len(substitutions):
            logger.debug("Failing on lens: %d vs %d",
                         len(placeholders), len(substitutions))
            return False
        if max(placeholders, key=lambda k: k[0])[0] > len(substitutions):
            logger.debug("Failing on max index: %d vs %d",
                         max(placeholders, key=lambda k: k[0])[0],
                         len(substitutions))
            return False

        # it seems that some templates request different values than what are subsequently put in them
        #   specifically, a Hex64 might be put into a SizeType field (EID 4624)
        # this maps from the type described in a template, to possible additional types that a
        #   record can provide for a particular substitution
        overrides = {
            16: set([21])
        }

        for index, type_, is_conditional in placeholders:
            sub_type, sub_value = substitutions[index]
            if is_conditional and sub_type == 0:
                continue
            if sub_type != type_:
                if type_ not in overrides or sub_type not in overrides[type_]:
                    logger.debug("Failing on type comparison, index %d: %d vs %d (mode: %s)",
                                 index, sub_type, type_, is_conditional)
                    return False
                else:
                    logger.debug("Overriding template type %d with substitution type %d", type_, sub_type)
                    continue
        return True

    escape_re = re.compile(r"\\\\(\d)")

    @staticmethod
    def _escape(value):
        """
        Escape the static value to be used in a regular expression
          subsititution. This processes any backreferences and
          makes them plain, escaped sequences.

        @type value: str
        @rtype: str
        """
        return Template.escape_re.sub(r"\\\\\\\\\1", re.escape(value))

    def insert_substitutions(self, substitutions):
        """
        Return a copy of the template with the given substitutions inserted.

        @type substitutions: list of (int, str)
        @param substitutions: an ordered list of (type:int, value:str)
        @rtype: str
        """
        ret = self._xml
        for index, pair in enumerate(substitutions):
            type_, value = pair
            from_pattern = "\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % index
            ret = re.sub(from_pattern, Template._escape(value), ret)
        return ret


class TemplateDatabase(object):
    """
    Class that loads and saves Templates to a persistent file.
    """
    def __init__(self, filename):
        self._filename = filename
        # this is a JSON-compatible structure that is truth
        #   see README for schema
        self._state = {}

        # this is a cache of instantiated Templates. it is not persisted to disk
        #   but loaded instances should always match whats in self._state
        #   not all instances may be loaded at any given time, however
        # schema is similar to state.templates:
        #   (str)eid -> list of Template instances
        self._cached_templates = {}

    def __enter__(self):
        if not os.path.exists(self._filename):
            logger.debug("Creating template file: %s", self._filename)
            touch(self._filename)
        else:
            logger.debug("Using existing template file: %s", self._filename)

        with open(self._filename, "rb") as f:
            self._state = json.loads(f.read() or "{}")

        if self._get_version() != CURRENT_VERSION and self._get_version() != "":
            raise IncompatibleVersionException("Version %d expected, got %d" %
                                               (CURRENT_VERSION, self._get_version()))

        self._set_version(CURRENT_VERSION)
        if self._get_generator() == "":
            self._set_generator(GENERATOR)
        return self

    def __exit__(self, type_, value, traceback):
        if not os.path.exists(self._filename):
            logger.debug("Creating template file: %s", self._filename)
            touch(self._filename)
        else:
            logger.debug("Using existing template file: %s", self._filename)

        with open(self._filename, "wb") as f:
            f.write(json.dumps(self._state, sort_keys=True,
                               indent=4, separators=(',', ': ')))
        if value:
            logging.warn("Flushing the existing template file due to exception.")
            return False

    def _set_version(self, version):
        self._state["version"] = version

    def _get_version(self):
        return self._state.get("version", "")

    def _set_generator(self, generator):
        self._state["generator"] = generator

    def _get_generator(self):
        return self._state.get("generator", "")

    def add_template(self, template):
        """
        @type template: Template
        """
        eid = template.get_eid()
        xml = template.get_xml()
        id_ = template.get_id()

        all_templates = self._state.get("templates", {})
        correct_eid_templates = all_templates.get(str(eid), [])
        if not exists(lambda t: t["id"] == id_ and
                                t["xml"] == xml, correct_eid_templates):
            correct_eid_templates.append({
                "eid": eid,
                "id": id_,
                "xml": xml
            })
            all_templates[eid] = correct_eid_templates
        self._state["templates"] = all_templates

        correct_eid_template_instances = self._cached_templates.get(str(eid), [])
        if not exists(lambda t: t.get_id() == id_ and
                                t.get_xml() == xml, correct_eid_template_instances):
            correct_eid_template_instances.append(template)
            self._cached_templates[str(eid)] = correct_eid_template_instances

    def get_template(self, eid, substitutions):
        """
        Given an EID and a set of substitutions, pick a template that
          matches the constraints.

        @type eid: int
        @type substitutions: list of (int, str)
        @rtype: Template
        @raises TemplateEIDConflictError
        @raises TemplateNotFoundError
        """
        if str(eid) not in self._cached_templates:
            all_templates = self._state.get("templates", {})
            if str(eid) not in all_templates:
                raise TemplateNotFoundError("No loaded templates with EID: %s" % eid)

            # need to load cache
            potential_templates = all_templates.get(str(eid), [])
            potential_templates = map(lambda t: Template(eid, t["xml"]), potential_templates)
            self._cached_templates[str(eid)] = potential_templates
        else:
            # already in cache
            potential_templates = self._cached_templates[str(eid)]

        matching_templates = []
        logger.debug("considering %d possible templates based on EID", len(potential_templates))
        for template in potential_templates:
            if template.match_substitutions(substitutions):
                matching_templates.append(template)

        if len(matching_templates) > 1:
            matches = map(lambda t: t.get_id(), matching_templates)
            raise TemplateEIDConflictError("%d templates matched query for "
                                           "EID %d and substitutions: %s" %
                                           (len(matching_templates), eid, matches))

        if len(matching_templates) == 0:
            # example: "1100-[0|4| ]-[1|4| ]-[2|6| ]-[3|6| ]"
            sig = str(eid) + "-" + "-".join(["[%d|%d| ]" % (i, j) for i, j in \
                                                 enumerate(map(lambda p: p[0], substitutions))])
            raise TemplateNotFoundError("No loaded templates with given "
                                        "substitution signature: %s" % sig)

        return matching_templates[0]

    def get_number_of_templates(self):
        """
        Get the number of templates tracked in this database.

        @rtype: int
        @return: The number of templates tracked in this database.
        """
        return sum(map(len, self._state.get("templates", {}).values()))


###################
#   BinaryParser
###################

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

##################################
#   Nodes
##################################

class SYSTEM_TOKENS:
    EndOfStreamToken = 0x00
    OpenStartElementToken = 0x01
    CloseStartElementToken = 0x02
    CloseEmptyElementToken = 0x03
    CloseElementToken = 0x04
    ValueToken = 0x05
    AttributeToken = 0x06
    CDataSectionToken = 0x07
    EntityReferenceToken = 0x08
    ProcessingInstructionTargetToken = 0x0A
    ProcessingInstructionDataToken = 0x0B
    TemplateInstanceToken = 0x0C
    NormalSubstitutionToken = 0x0D
    ConditionalSubstitutionToken = 0x0E
    StartOfStreamToken = 0x0F


node_dispatch_table = []  # updated at end of file
node_readable_tokens = []  # updated at end of file


class SuppressConditionalSubstitution(Exception):
    """
    This exception is to be thrown to indicate that a conditional
      substitution evaluated to NULL, and the parent element should
      be suppressed. This exception should be caught at the first
      opportunity, and must not propagate far up the call chain.

    Strategy:
      AttributeNode catches this, .xml() --> ""
      StartOpenElementNode catches this for each child, ensures
        there's at least one useful value.  Or, .xml() --> ""
    """
    def __init__(self, msg):
        super(SuppressConditionalSubstitution, self).__init__(msg)


class UnexpectedStateException(ParseException):
    """
    UnexpectedStateException is an exception to be thrown when the parser
      encounters an unexpected value or state. This probably means there
      is a bug in the parser, but could stem from a corrupted input file.
    """
    def __init__(self, msg):
        super(UnexpectedStateException, self).__init__(msg)


class BXmlNode(Block):

    def __init__(self, buf, offset, chunk, parent):
        super(BXmlNode, self).__init__(buf, offset)
        self._chunk = chunk
        self._parent = parent

    def __repr__(self):
        return "BXmlNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "BXmlNode(offset=%s)" % (hex(self.offset()))

    def dump(self):
        return hex_dump(self._buf[self.offset():self.offset() + self.length()],
                        start_addr=self.offset())

    def tag_length(self):
        """
        This method must be implemented and overridden for all BXmlNodes.
        @return An integer specifying the length of this tag, not including
          its children.
        """
        raise NotImplementedError("tag_length not implemented for %r") % \
            (self)

    def _children(self, max_children=None,
                  end_tokens=[SYSTEM_TOKENS.EndOfStreamToken]):
        """
        @return A list containing all of the children BXmlNodes.
        """
        ret = []
        ofs = self.tag_length()

        if max_children:
            gen = xrange(max_children)
        else:
            gen = itertools.count()

        for _ in gen:
            # we lose error checking by masking off the higher nibble,
            #   but, some tokens like 0x01, make use of the flags nibble.
            token = self.unpack_byte(ofs) & 0x0F
            try:
                HandlerNodeClass = node_dispatch_table[token]
                child = HandlerNodeClass(self._buf, self.offset() + ofs,
                                         self._chunk, self)
            except IndexError:
                raise ParseException("Unexpected token %02X at %s" % \
                                         (token,
                                          self.absolute_offset(0x0) + ofs))
            ret.append(child)
            ofs += child.length()
            if token in end_tokens:
                break
            if child.find_end_of_stream():
                break
        return ret

    @memoize
    def children(self):
        return self._children()

    @memoize
    def length(self):
        """
        @return An integer specifying the length of this tag and all
          its children.
        """
        ret = self.tag_length()
        for child in self.children():
            ret += child.length()
        return ret

    @memoize
    def find_end_of_stream(self):
        for child in self.children():
            if isinstance(child, EndOfStreamNode):
                return child
            ret = child.find_end_of_stream()
            if ret:
                return ret
        return None


class NameStringNode(BXmlNode):
    def __init__(self, buf, offset, chunk, parent):
        super(NameStringNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("dword", "next_offset", 0x0)
        self.declare_field("word", "hash")
        self.declare_field("word", "string_length")
        self.declare_field("wstring", "string", length=self.string_length())

    def __repr__(self):
        return "NameStringNode(buf=%r, offset=%r, chunk=%r)" % \
            (self._buf, self.offset(), self._chunk)

    def __str__(self):
        return "NameStringNode(offset=%s, length=%s, end=%s)" % \
            (hex(self.offset()), hex(self.length()),
             hex(self.offset() + self.length()))

    def string(self):
        return str(self._string())

    def tag_length(self):
        return (self.string_length() * 2) + 8

    def length(self):
        # two bytes unaccounted for...
        return self.tag_length() + 2


class TemplateNode(BXmlNode):
    def __init__(self, buf, offset, chunk, parent):
        super(TemplateNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("dword", "next_offset", 0x0)
        self.declare_field("dword", "template_id")
        self.declare_field("guid",  "guid", 0x04)  # unsure why this overlaps
        self.declare_field("dword", "data_length")

    def __repr__(self):
        return "TemplateNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "TemplateNode(offset=%s, guid=%s, length=%s)" % \
            (hex(self.offset()), self.guid(), hex(self.length()))

    def tag_length(self):
        return 0x18

    def length(self):
        return self.tag_length() + self.data_length()


class EndOfStreamNode(BXmlNode):
    """
    The binary XML node for the system token 0x00.

    This is the "end of stream" token. It may never actually
      be instantiated here.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(EndOfStreamNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "EndOfStreamNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "EndOfStreamNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), 0x00)

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []


class OpenStartElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x01.

    This is the "open start element" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(OpenStartElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "unknown0")
        # TODO(wb): use this size() field.
        self.declare_field("dword", "size")
        self.declare_field("dword", "string_offset")
        self._tag_length = 11
        self._element_type = 0

        if self.flags() & 0x04:
            self._tag_length += 4

        if self.string_offset() > self.offset() - self._chunk._offset:
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._tag_length += new_string.length()

    def __repr__(self):
        return "OpenStartElementNode(buf=%r, offset=%r, chunk=%r)" % \
            (self._buf, self.offset(), self._chunk)

    def __str__(self):
        return "OpenStartElementNode(offset=%s, name=%s, length=%s, token=%s, end=%s, taglength=%s, endtag=%s)" % \
            (hex(self.offset()), self.tag_name(),
             hex(self.length()), hex(self.token()),
             hex(self.offset() + self.length()),
             hex(self.tag_length()),
             hex(self.offset() + self.tag_length()))

    @memoize
    def is_empty_node(self):
        for child in self.children():
            if type(child) is CloseEmptyElementNode:
                return True
        return False

    def flags(self):
        return self.token() >> 4

    @memoize
    def tag_name(self):
        return self._chunk.strings()[self.string_offset()].string()

    def tag_length(self):
        return self._tag_length

    def verify(self):
        return self.flags() & 0x0b == 0 and \
            self.opcode() & 0x0F == 0x01

    @memoize
    def children(self):
        return self._children(end_tokens=[SYSTEM_TOKENS.CloseElementToken,
                                          SYSTEM_TOKENS.CloseEmptyElementToken])


class CloseStartElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x02.

    This is the "close start element" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(CloseStartElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseStartElementNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CloseStartElementNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()))

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []

    def verify(self):
        return self.flags() & 0x0F == 0 and \
            self.opcode() & 0x0F == 0x02


class CloseEmptyElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x03.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(CloseEmptyElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseEmptyElementNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CloseEmptyElementNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x03))

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []


class CloseElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x04.

    This is the "close element" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(CloseElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseElementNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CloseElementNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()))

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []

    def verify(self):
        return self.flags() & 0x0F == 0 and \
            self.opcode() & 0x0F == 0x04


def get_variant_value(buf, offset, chunk, parent, type_, length=None):
    """
    @return A VariantType subclass instance found in the given
      buffer and offset.
    """
    types = {
        0x00: NullTypeNode,
        0x01: WstringTypeNode,
        0x02: StringTypeNode,
        0x03: SignedByteTypeNode,
        0x04: UnsignedByteTypeNode,
        0x05: SignedWordTypeNode,
        0x06: UnsignedWordTypeNode,
        0x07: SignedDwordTypeNode,
        0x08: UnsignedDwordTypeNode,
        0x09: SignedQwordTypeNode,
        0x0A: UnsignedQwordTypeNode,
        0x0B: FloatTypeNode,
        0x0C: DoubleTypeNode,
        0x0D: BooleanTypeNode,
        0x0E: BinaryTypeNode,
        0x0F: GuidTypeNode,
        0x10: SizeTypeNode,
        0x11: FiletimeTypeNode,
        0x12: SystemtimeTypeNode,
        0x13: SIDTypeNode,
        0x14: Hex32TypeNode,
        0x15: Hex64TypeNode,
        0x21: BXmlTypeNode,
        0x81: WstringArrayTypeNode,
    }
    try:
        TypeClass = types[type_]
    except IndexError:
        raise NotImplementedError("Type %s not implemented" % (type_))
    return TypeClass(buf, offset, chunk, parent, length=length)


class ValueNode(BXmlNode):
    """
    The binary XML node for the system token 0x05.

    This is the "value" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(ValueNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "type")

    def __repr__(self):
        return "ValueNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ValueNode(offset=%s, length=%s, token=%s, value=%s)" % \
            (hex(self.offset()), hex(self.length()),
             hex(self.token()), self.value().string())

    def flags(self):
        return self.token() >> 4

    def value(self):
        return self.children()[0]

    def tag_length(self):
        return 2

    def children(self):
        child = get_variant_value(self._buf,
                                  self.offset() + self.tag_length(),
                                  self._chunk, self, self.type())
        return [child]

    def verify(self):
        return self.flags() & 0x0B == 0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.ValueToken


class AttributeNode(BXmlNode):
    """
    The binary XML node for the system token 0x06.

    This is the "attribute" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(AttributeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")

        self._name_string_length = 0
        if self.string_offset() > self.offset() - self._chunk._offset:
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._name_string_length += new_string.length()

    def __repr__(self):
        return "AttributeNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "AttributeNode(offset=%s, length=%s, token=%s, name=%s, value=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()),
             self.attribute_name(), self.attribute_value())

    def flags(self):
        return self.token() >> 4

    def attribute_name(self):
        """
        @return A NameNode instance that contains the attribute name.
        """
        return self._chunk.strings()[self.string_offset()]

    def attribute_value(self):
        """
        @return A BXmlNode instance that is one of (ValueNode,
          ConditionalSubstitutionNode, NormalSubstitutionNode).
        """
        return self.children()[0]

    def tag_length(self):
        return 5 + self._name_string_length

    def verify(self):
        return self.flags() & 0x0B == 0 and \
            self.opcode() & 0x0F == 0x06

    @memoize
    def children(self):
        return self._children(max_children=1)


class CDataSectionNode(BXmlNode):
    """
    The binary XML node for the system token 0x07.

    This is the "CDATA section" system token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(CDataSectionNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "string_length")
        self.declare_field("wstring", "cdata", length=self.string_length() - 2)

    def __repr__(self):
        return "CDataSectionNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CDataSectionNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), 0x07)

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 0x3 + self.string_length()

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0x0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.CDataSectionToken


class EntityReferenceNode(BXmlNode):
    """
    The binary XML node for the system token 0x09.

    This is an entity reference node.  That is, something that represents
      a non-XML character, eg. & --> &amp;.

    TODO(wb): this is untested.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(EntityReferenceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")
        self._tag_length = 5

        if self.string_offset() > self.offset() - self._chunk.offset():
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._tag_length += new_string.length()


    def __repr__(self):
        return "EntityReferenceNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "EntityReferenceNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x09))

    def entity_reference(self):
        return "&%s;" % \
            (self._chunk.strings()[self.string_offset()].string())

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return self._tag_length

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        return []


class ProcessingInstructionTargetNode(BXmlNode):
    """
    The binary XML node for the system token 0x0A.

    TODO(wb): untested.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(ProcessingInstructionTargetNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")
        self._tag_length = 5

        if self.string_offset() > self.offset() - self._chunk.offset():
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._tag_length += new_string.length()

    def __repr__(self):
        return "ProcessingInstructionTargetNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ProcessingInstructionTargetNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x0A))

    def processing_instruction_target(self):
        return "<?%s" % \
            (self._chunk.strings()[self.string_offset()].string())

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return self._tag_length

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        return []


class ProcessingInstructionDataNode(BXmlNode):
    """
    The binary XML node for the system token 0x0B.

    TODO(wb): untested.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(ProcessingInstructionDataNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "string_length")
        self._tag_length = 3 + (2 * self.string_length())

        if self.string_length() > 0:
            self._string = self.unpack_wstring(0x3, self.string_length())
        else:
            self._string = ""

    def __repr__(self):
        return "ProcessingInstructionDataNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ProcessingInstructionDataNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x0B))

    def flags(self):
        return self.token() >> 4

    def string(self):
        if self.string_length() > 0:
            return " %s?>" % (self._string)
        else:
            return "?>"

    def tag_length(self):
        return self._tag_length

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        return []


class TemplateInstanceNode(BXmlNode):
    """
    The binary XML node for the system token 0x0C.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(TemplateInstanceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "unknown0")
        self.declare_field("dword", "template_id")
        self.declare_field("dword", "template_offset")

        self._data_length = 0

        if self.is_resident_template():
            new_template = self._chunk.add_template(self.template_offset(),
                                                    parent=self)
            self._data_length += new_template.length()

    def __repr__(self):
        return "TemplateInstanceNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "TemplateInstanceNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x0C))

    def flags(self):
        return self.token() >> 4

    def is_resident_template(self):
        return self.template_offset() > self.offset() - self._chunk._offset

    def tag_length(self):
        return 10

    def length(self):
        return self.tag_length() + self._data_length

    def template(self):
        return self._chunk.templates()[self.template_offset()]

    def children(self):
        return []

    @memoize
    def find_end_of_stream(self):
        return self.template().find_end_of_stream()


class NormalSubstitutionNode(BXmlNode):
    """
    The binary XML node for the system token 0x0D.

    This is a "normal substitution" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(NormalSubstitutionNode, self).__init__(buf, offset,
                                                     chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "index")
        self.declare_field("byte", "type")

    def __repr__(self):
        return "NormalSubstitutionNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "NormalSubstitutionNode(offset=%s, length=%s, token=%s, index=%d, type=%d)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()),
             self.index(), self.type())

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 0x4

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.NormalSubstitutionToken


class ConditionalSubstitutionNode(BXmlNode):
    """
    The binary XML node for the system token 0x0E.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(ConditionalSubstitutionNode, self).__init__(buf, offset,
                                                          chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "index")
        self.declare_field("byte", "type")

    def __repr__(self):
        return "ConditionalSubstitutionNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ConditionalSubstitutionNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x0E))

    def should_suppress(self, substitutions):
        sub = substitutions[self.index()]
        return type(sub) is NullTypeNode

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 0x4

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.ConditionalSubstitutionToken


class StreamStartNode(BXmlNode):
    """
    The binary XML node for the system token 0x0F.

    This is the "start of stream" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(StreamStartNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "unknown0")
        self.declare_field("word", "unknown1")

    def __repr__(self):
        return "StreamStartNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "StreamStartNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()))

    def verify(self):
        return self.flags() == 0x0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.StartOfStreamToken and \
            self.unknown0() == 0x1 and \
            self.unknown1() == 0x1

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 4

    def length(self):
        return self.tag_length() + 0

    def children(self):
        return []


class RootNode(BXmlNode):
    """
    The binary XML node for the Root node.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(RootNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "RootNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "RootNode(offset=%s, length=%s)" % \
            (hex(self.offset()), hex(self.length()))

    def tag_length(self):
        return 0

    @memoize
    def children(self):
        """
        @return The template instances which make up this node.
        """
        return self._children(end_tokens=[SYSTEM_TOKENS.EndOfStreamToken])

    def tag_and_children_length(self):
        """
        @return The length of the tag of this element, and the children.
          This does not take into account the substitutions that may be
          at the end of this element.
        """
        children_length = 0

        for child in self.children():
            children_length += child.length()

        return self.tag_length() + children_length

    def fast_template_instance(self):
        ofs = self.offset()
        if self.unpack_byte(0x0) & 0x0F == 0xF:
            ofs += 4
        return TemplateInstanceNode(self._buf, ofs, self._chunk, self)

    @memoize
    def fast_substitutions(self):
        """
        Get the list of elements that are the
          the substitutions for this root node.
          Each element is one of:
            str
            int
            float
            RootNode
        @rtype: list
        """
        sub_decl = []
        sub_def = []
        ofs = self.tag_and_children_length()
        sub_count = self.unpack_dword(ofs)
        ofs += 4
        for _ in xrange(sub_count):
            size = self.unpack_word(ofs)
            type_ = self.unpack_byte(ofs + 0x2)
            sub_decl.append((size, type_))
            ofs += 4
        for (size, type_) in sub_decl:
            #[0] = parse_null_type_node,
            if type_ == 0x0:
                value = None
                sub_def.append(value)
            #[1] = parse_wstring_type_node,
            elif type_ == 0x1:
                s = self.unpack_wstring(ofs, size / 2).rstrip("\x00")
                value = s.replace("<", "&gt;").replace(">", "&lt;")
                sub_def.append(value)
            #[2] = parse_string_type_node,
            elif type_ == 0x2:
                s = self.unpack_string(ofs, size)
                value = s.decode("utf8").rstrip("\x00")
                value = value.replace("<", "&gt;")
                value = value.replace(">", "&lt;")
                sub_def.append(value)
            #[3] = parse_signed_byte_type_node,
            elif type_ == 0x3:
                sub_def.append(self.unpack_int8(ofs))
            #[4] = parse_unsigned_byte_type_node,
            elif type_ == 0x4:
                sub_def.append(self.unpack_byte(ofs))
            #[5] = parse_signed_word_type_node,
            elif type_ == 0x5:
                sub_def.append(self.unpack_int16(ofs))
            #[6] = parse_unsigned_word_type_node,
            elif type_ == 0x6:
                sub_def.append(self.unpack_word(ofs))
            #[7] = parse_signed_dword_type_node,
            elif type_ == 0x7:
                sub_def.append(self.unpack_int32(ofs))
            #[8] = parse_unsigned_dword_type_node,
            elif type_ == 0x8:
                sub_def.append(self.unpack_dword(ofs))
            #[9] = parse_signed_qword_type_node,
            elif type_ == 0x9:
                sub_def.append(self.unpack_int64(ofs))
            #[10] = parse_unsigned_qword_type_node,
            elif type_ == 0xA:
                sub_def.append(self.unpack_qword(ofs))
            #[11] = parse_float_type_node,
            elif type_ == 0xB:
                sub_def.append(self.unpack_float(ofs))
            #[12] = parse_double_type_node,
            elif type_ == 0xC:
                sub_def.append(self.unpack_double(ofs))
            #[13] = parse_boolean_type_node,
            elif type_ == 0xD:
                sub_def.append(str(self.unpack_word(ofs) > 1))
            #[14] = parse_binary_type_node,
            elif type_ == 0xE:
                sub_def.append(base64.b64encode(self.unpack_binary(ofs, size)))
            #[15] = parse_guid_type_node,
            elif type_ == 0xF:
                sub_def.append(self.unpack_guid(ofs))
            #[16] = parse_size_type_node,
            elif type_ == 0x10:
                if size == 0x4:
                    sub_def.append(self.unpack_dword(ofs))
                elif size == 0x8:
                    sub_def.append(self.unpack_qword(ofs))
                else:
                    raise UnexpectedStateException("Unexpected size for SizeTypeNode: %s" % hex(size))
            #[17] = parse_filetime_type_node,
            elif type_ == 0x11:
                sub_def.append(self.unpack_filetime(ofs))
            #[18] = parse_systemtime_type_node,
            elif type_ == 0x12:
                sub_def.append(self.unpack_systemtime(ofs))
            #[19] = parse_sid_type_node,  -- SIDTypeNode, 0x13
            elif type_ == 0x13:
                version = self.unpack_byte(ofs)
                num_elements = self.unpack_byte(ofs + 1)
                id_high = self.unpack_dword_be(ofs + 2)
                id_low = self.unpack_word_be(ofs + 6)
                value = "S-%d-%d" % (version, (id_high << 16) ^ id_low)
                for i in xrange(num_elements):
                    val = self.unpack_dword(ofs + 8 + (4 * i))
                    value += "-%d" % val
                sub_def.append(value)
            #[20] = parse_hex32_type_node,  -- Hex32TypeNoe, 0x14
            elif type_ == 0x14:
                value = "0x"
                for c in self.unpack_binary(ofs, size)[::-1]:
                    value += "%02x" % ord(c)
                sub_def.append(value)
            #[21] = parse_hex64_type_node,  -- Hex64TypeNode, 0x15
            elif type_ == 0x15:
                value = "0x"
                for c in self.unpack_binary(ofs, size)[::-1]:
                    value += "%02x" % ord(c)
                sub_def.append(value)
            #[33] = parse_bxml_type_node,  -- BXmlTypeNode, 0x21
            elif type_ == 0x21:
                sub_def.append(RootNode(self._buf, self.offset() + ofs,
                                        self._chunk, self))
            #[129] = TODO, -- WstringArrayTypeNode, 0x81
            elif type_ == 0x81:
                bin = self.unpack_binary(ofs, size)
                acc = []
                while len(bin) > 0:
                    match = re.search("((?:[^\x00].)+)", bin)
                    if match:
                        frag = match.group()
                        acc.append("<string>")
                        acc.append(frag.decode("utf16"))
                        acc.append("</string>\n")
                        bin = bin[len(frag) + 2:]
                        if len(bin) == 0:
                            break
                    frag = re.search("(\x00*)", bin).group()
                    if len(frag) % 2 == 0:
                        for _ in xrange(len(frag) // 2):
                            acc.append("<string></string>\n")
                    else:
                        raise ParseException("Error parsing uneven substring of NULLs")
                    bin = bin[len(frag):]
                sub_def.append("".join(acc))
            else:
                raise "Unexpected type encountered: %s" % hex(type_)
            ofs += size
        return sub_def

    @memoize
    def substitutions(self):
        """
        @return A list of VariantTypeNode subclass instances that
          contain the substitutions for this root node.
        """
        sub_decl = []
        sub_def = []
        ofs = self.tag_and_children_length()
        sub_count = self.unpack_dword(ofs)
        ofs += 4
        for _ in xrange(sub_count):
            size = self.unpack_word(ofs)
            type_ = self.unpack_byte(ofs + 0x2)
            sub_decl.append((size, type_))
            ofs += 4
        for (size, type_) in sub_decl:
            val = get_variant_value(self._buf, self.offset() + ofs,
                                    self._chunk, self, type_, length=size)
            if abs(size - val.length()) > 4:
                # TODO(wb): This is a hack, so I'm sorry.
                #   But, we are not passing around a 'length' field,
                #   so we have to depend on the structure of each
                #   variant type.  It seems some BXmlTypeNode sizes
                #   are not exact.  Hopefully, this is just alignment.
                #   So, that's what we compensate for here.
                raise ParseException("Invalid substitution value size")
            sub_def.append(val)
            ofs += size
        return sub_def

    @memoize
    def length(self):
        ofs = self.tag_and_children_length()
        sub_count = self.unpack_dword(ofs)
        ofs += 4
        ret = ofs
        for _ in xrange(sub_count):
            size = self.unpack_word(ofs)
            ret += size + 4
            ofs += 4
        return ret


class VariantTypeNode(BXmlNode):
    """

    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(VariantTypeNode, self).__init__(buf, offset, chunk, parent)
        self._length = length

    def __repr__(self):
        return "%s(buf=%r, offset=%s, chunk=%r)" % \
            (self.__class__.__name__, self._buf, hex(self.offset()),
             self._chunk)

    def __str__(self):
        return "%s(offset=%s, length=%s, string=%s)" % \
            (self.__class__.__name__, hex(self.offset()),
             hex(self.length()), self.string())

    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for %r" % \
                                      (self))

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def string(self):
        raise NotImplementedError("string not implemented for %r" % \
                                      (self))


class NullTypeNode(object):  # but satisfies the contract of VariantTypeNode, BXmlNode, but not Block
    """
    Variant type 0x00.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(NullTypeNode, self).__init__()
        self._offset = offset
        self._length = length

    def __str__(self):
        return "NullTypeNode"

    def string(self):
        return ""

    def length(self):
        return self._length or 0

    def tag_length(self):
        return self._length or 0

    def children(self):
        return []

    def offset(self):
        return self._offset


class WstringTypeNode(VariantTypeNode):
    """
    Variant ttype 0x01.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(WstringTypeNode, self).__init__(buf, offset, chunk,
                                              parent, length=length)
        if self._length is None:
            self.declare_field("word",    "string_length", 0x0)
            self.declare_field("wstring", "_string",
                               length=(self.string_length()))
        else:
            self.declare_field("wstring", "_string", 0x0,
                               length=(self._length / 2))

    def tag_length(self):
        if self._length is None:
            return (2 + (self.string_length() * 2))
        return self._length

    def string(self):
        return self._string().rstrip("\x00")


class StringTypeNode(VariantTypeNode):
    """
    Variant type 0x02.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(StringTypeNode, self).__init__(buf, offset, chunk,
                                             parent, length=length)
        if self._length is None:
            self.declare_field("word",   "string_length", 0x0)
            self.declare_field("string", "_string",
                               length=(self.string_length()))
        else:
            self.declare_field("string", "_string", 0x0, length=self._length)

    def tag_length(self):
        if self._length is None:
            return (2 + (self.string_length()))
        return self._length

    def string(self):
        return self._string().rstrip("\x00")


class SignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x03.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedByteTypeNode, self).__init__(buf, offset, chunk,
                                                 parent, length=length)
        self.declare_field("int8", "byte", 0x0)

    def tag_length(self):
        return 1

    def string(self):
        return str(self.byte())


class UnsignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x04.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedByteTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                   length=length)
        self.declare_field("byte", "byte", 0x0)

    def tag_length(self):
        return 1

    def string(self):
        return str(self.byte())


class SignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x05.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedWordTypeNode, self).__init__(buf, offset, chunk,
                                                 parent, length=length)
        self.declare_field("int16", "word", 0x0)

    def tag_length(self):
        return 2

    def string(self):
        return str(self.word())


class UnsignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x06.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedWordTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                   length=length)
        self.declare_field("word", "word", 0x0)

    def tag_length(self):
        return 2

    def string(self):
        return str(self.word())


class SignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x07.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedDwordTypeNode, self).__init__(buf, offset, chunk,
                                                  parent, length=length)
        self.declare_field("int32", "dword", 0x0)

    def tag_length(self):
        return 4

    def string(self):
        return str(self.dword())


class UnsignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x08.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedDwordTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                    length=length)
        self.declare_field("dword", "dword", 0x0)

    def tag_length(self):
        return 4

    def string(self):
        return str(self.dword())


class SignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x09.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedQwordTypeNode, self).__init__(buf, offset, chunk,
                                                  parent, length=length)
        self.declare_field("int64", "qword", 0x0)

    def tag_length(self):
        return 8

    def string(self):
        return str(self.qword())


class UnsignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x0A.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedQwordTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                    length=length)
        self.declare_field("qword", "qword", 0x0)

    def tag_length(self):
        return 8

    def string(self):
        return str(self.qword())


class FloatTypeNode(VariantTypeNode):
    """
    Variant type 0x0B.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(FloatTypeNode, self).__init__(buf, offset, chunk,
                                            parent, length=length)
        self.declare_field("float", "float", 0x0)

    def tag_length(self):
        return 4

    def string(self):
        return str(self.float())


class DoubleTypeNode(VariantTypeNode):
    """
    Variant type 0x0C.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(DoubleTypeNode, self).__init__(buf, offset, chunk,
                                             parent, length=length)
        self.declare_field("double", "double", 0x0)

    def tag_length(self):
        return 8

    def string(self):
        return str(self.double())


class BooleanTypeNode(VariantTypeNode):
    """
    Variant type 0x0D.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(BooleanTypeNode, self).__init__(buf, offset, chunk,
                                              parent, length=length)
        self.declare_field("int32", "int32", 0x0)

    def tag_length(self):
        return 4

    def string(self):
        if self.int32 > 0:
            return "True"
        return "False"


class BinaryTypeNode(VariantTypeNode):
    """
    Variant type 0x0E.

    String/XML representation is Base64 encoded.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(BinaryTypeNode, self).__init__(buf, offset, chunk,
                                             parent, length=length)
        if self._length is None:
            self.declare_field("dword", "size", 0x0)
            self.declare_field("binary", "binary", length=self.size())
        else:
            self.declare_field("binary", "binary", 0x0, length=self._length)

    def tag_length(self):
        if self._length is None:
            return (4 + self.size())
        return self._length

    def string(self):
        return base64.b64encode(self.binary())


class GuidTypeNode(VariantTypeNode):
    """
    Variant type 0x0F.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(GuidTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)
        self.declare_field("guid", "guid", 0x0)

    def tag_length(self):
        return 16

    def string(self):
        return "{%s}" % (self.guid())


class SizeTypeNode(VariantTypeNode):
    """
    Variant type 0x10.

    Note: Assuming sizeof(size_t) == 0x8.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SizeTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)
        if self._length == 0x4:
            self.declare_field("dword", "num", 0x0)
        elif self._length == 0x8:
            self.declare_field("qword", "num", 0x0)
        else:
            self.declare_field("qword", "num", 0x0)

    def tag_length(self):
        if self._length is None:
            return 8
        return self._length

    def string(self):
        return str(self.num())


class FiletimeTypeNode(VariantTypeNode):
    """
    Variant type 0x11.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(FiletimeTypeNode, self).__init__(buf, offset, chunk,
                                               parent, length=length)
        self.declare_field("filetime", "filetime", 0x0)

    def string(self):
        return self.filetime().isoformat("T") + "Z"

    def tag_length(self):
        return 8


class SystemtimeTypeNode(VariantTypeNode):
    """
    Variant type 0x12.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SystemtimeTypeNode, self).__init__(buf, offset, chunk,
                                                 parent, length=length)
        self.declare_field("systemtime", "systemtime", 0x0)

    def tag_length(self):
        return 16

    def string(self):
        return self.systemtime().isoformat("T") + "Z"


class SIDTypeNode(VariantTypeNode):
    """
    Variant type 0x13.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SIDTypeNode, self).__init__(buf, offset, chunk,
                                          parent, length=length)
        self.declare_field("byte",  "version", 0x0)
        self.declare_field("byte",  "num_elements")
        self.declare_field("dword_be", "id_high")
        self.declare_field("word_be",  "id_low")

    @memoize
    def elements(self):
        ret = []
        for i in xrange(self.num_elements()):
            ret.append(self.unpack_dword(self.current_field_offset() + 4 * i))
        return ret

    @memoize
    def id(self):
        ret = "S-%d-%d" % \
            (self.version(), (self.id_high() << 16) ^ self.id_low())
        for elem in self.elements():
            ret += "-%d" % (elem)
        return ret

    def tag_length(self):
        return 8 + 4 * self.num_elements()

    def string(self):
        return self.id()


class Hex32TypeNode(VariantTypeNode):
    """
    Variant type 0x14.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(Hex32TypeNode, self).__init__(buf, offset, chunk,
                                            parent, length=length)
        self.declare_field("binary", "hex", 0x0, length=0x4)

    def tag_length(self):
        return 4

    def string(self):
        ret = "0x"
        for c in self.hex()[::-1]:
            ret += "%02x" % (ord(c))
        return ret


class Hex64TypeNode(VariantTypeNode):
    """
    Variant type 0x15.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(Hex64TypeNode, self).__init__(buf, offset, chunk,
                                            parent, length=length)
        self.declare_field("binary", "hex", 0x0, length=0x8)

    def tag_length(self):
        return 8

    def string(self):
        ret = "0x"
        for c in self.hex()[::-1]:
            ret += "%02x" % (ord(c))
        return ret


class BXmlTypeNode(VariantTypeNode):
    """
    Variant type 0x21.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(BXmlTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)
        self._root = RootNode(buf, offset, chunk, self)

    def tag_length(self):
        return self._length or self._root.length()

    def string(self):
        return str(self._root)

    def root(self):
        return self._root


class WstringArrayTypeNode(VariantTypeNode):
    """
    Variant ttype 0x81.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(WstringArrayTypeNode, self).__init__(buf, offset, chunk,
                                              parent, length=length)
        if self._length is None:
            self.declare_field("word",   "binary_length", 0x0)
            self.declare_field("binary", "binary",
                               length=(self.binary_length()))
        else:
            self.declare_field("binary", "binary", 0x0,
                               length=(self._length))

    def tag_length(self):
        if self._length is None:
            return (2 + self.binary_length())
        return self._length

    def string(self):
        bin = self.binary()
        acc = []
        while len(bin) > 0:
            match = re.search("((?:[^\x00].)+)", bin)
            if match:
                frag = match.group()
                acc.append("<string>")
                acc.append(frag.decode("utf16"))
                acc.append("</string>\n")
                bin = bin[len(frag) + 2:]
                if len(bin) == 0:
                    break
            frag = re.search("(\x00*)", bin).group()
            if len(frag) % 2 == 0:
                for _ in xrange(len(frag) // 2):
                    acc.append("<string></string>\n")
            else:
                raise "Error parsing uneven substring of NULLs"
            bin = bin[len(frag):]
        return "".join(acc)


node_dispatch_table = [
    EndOfStreamNode,
    OpenStartElementNode,
    CloseStartElementNode,
    CloseEmptyElementNode,
    CloseElementNode,
    ValueNode,
    AttributeNode,
    CDataSectionNode,
    None,
    EntityReferenceNode,
    ProcessingInstructionTargetNode,
    ProcessingInstructionDataNode,
    TemplateInstanceNode,
    NormalSubstitutionNode,
    ConditionalSubstitutionNode,
    StreamStartNode,
    ]

node_readable_tokens = [
    "End of Stream",
    "Open Start Element",
    "Close Start Element",
    "Close Empty Element",
    "Close Element",
    "Value",
    "Attribute",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "TemplateInstanceNode",
    "Normal Substitution",
    "Conditional Substitution",
    "Start of Stream",
    ]


#####################################
#   Views
#####################################

class UnexpectedElementException(Exception):
    def __init__(self, msg):
        super(UnexpectedElementException, self).__init__(msg)


def _make_template_xml_view(root_node, cache=None):
    """
    Given a RootNode, parse only the template/children
      and not the substitutions.

    Note, the cache should be local to the Evtx.Chunk.
      Do not share caches across Chunks.

    @type root_node: Nodes.RootNode
    @type cache: dict of {int: TemplateNode}
    @rtype: str
    """
    if cache is None:
        cache = {}

    def escape_format_chars(s):
        return s.replace("{", "{{").replace("}", "}}")

    def rec(node, acc):
        if isinstance(node, EndOfStreamNode):
            pass  # intended
        elif isinstance(node, OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, AttributeNode):
                    acc.append(" ")
                    acc.append(child.attribute_name().string())
                    acc.append("=\"")
                    rec(child.attribute_value(), acc)
                    acc.append("\"")
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(node.tag_name())
            acc.append(">\n")
        elif isinstance(node, CloseStartElementNode):
            pass  # intended
        elif isinstance(node, CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, CloseElementNode):
            pass  # intended
        elif isinstance(node, ValueNode):
            acc.append(escape_format_chars(node.children()[0].string()))
        elif isinstance(node, AttributeNode):
            pass  # intended
        elif isinstance(node, CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(node.cdata())
            acc.append("]]>")
        elif isinstance(node, EntityReferenceNode):
            acc.append(node.entity_reference())
        elif isinstance(node, ProcessingInstructionTargetNode):
            acc.append(node.processing_instruction_target())
        elif isinstance(node, ProcessingInstructionDataNode):
            acc.append(node.string())
        elif isinstance(node, TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, NormalSubstitutionNode):
            acc.append("{")
            acc.append("%d" % (node.index()))
            acc.append("}")
        elif isinstance(node, ConditionalSubstitutionNode):
            acc.append("{")
            acc.append("%d" % (node.index()))
            acc.append("}")
        elif isinstance(node, StreamStartNode):
            pass  # intended

    acc = []
    template_instance = root_node.fast_template_instance()
    templ_off = template_instance.template_offset() + \
        template_instance._chunk.offset()
    if templ_off in cache:
        acc.append(cache[templ_off])
    else:
        node = TemplateNode(template_instance._buf, templ_off,
                            template_instance._chunk, template_instance)
        sub_acc = []
        for c in node.children():
            rec(c, sub_acc)
        sub_templ = "".join(sub_acc)
        cache[templ_off] = sub_templ
        acc.append(sub_templ)
    return "".join(acc)


def _build_record_xml(record, cache=None):
    """
    Note, the cache should be local to the Evtx.Chunk.
      Do not share caches across Chunks.

    @type record: Evtx.Record
    @type cache: dict of {int: TemplateNode}
    @rtype: str
    """
    if cache is None:
        cache = {}

    def rec(root_node):
        f = _make_template_xml_view(root_node, cache=cache)
        subs_strs = []
        for sub in root_node.fast_substitutions():
            if isinstance(sub, basestring):
                subs_strs.append((xml_sax_escape(sub, {'"': "&quot;"})).encode("ascii", "xmlcharrefreplace"))
            elif isinstance(sub, RootNode):
                subs_strs.append(rec(sub))
            elif sub is None:
                subs_strs.append("")
            else:
                subs_strs.append(str(sub))
        return f.format(*subs_strs)
    xml = rec(record.root())
    return xml


def evtx_record_xml_view(record, cache=None):
    """
    Generate an UTF-8 XML representation of an EVTX record.

    Note, the cache should be local to the Evtx.Chunk.
      Do not share caches across Chunks.

    @type record: Evtx.Record
    @type cache: dict of {int: TemplateNode}
    @rtype: str
    """
    if cache is None:
        cache = {}
    return _build_record_xml(record, cache=cache).encode("utf8", "xmlcharrefreplace")


def evtx_chunk_xml_view(chunk):
    """
    Generate UTF-8 XML representations of the records in an EVTX chunk.

    Does not include the XML <?xml... header.
    Records are ordered by chunk.records()

    @type chunk: Evtx.Chunk
    @rtype: generator of str, Evtx.Record
    """
    cache = {}
    for record in chunk.records():
        record_str = _build_record_xml(record, cache=cache)
        yield record_str.encode("utf8", "xmlcharrefreplace"), record


def evtx_file_xml_view(file_header):
    """
    Generate UTF-8 XML representations of the records in an EVTX file.

    Does not include the XML <?xml... header.
    Records are ordered by file_header.chunks(), and then by chunk.records()

    @type file_header: Evtx.FileHeader
    @rtype: generator of str, Evtx.Record
    """
    for chunk in file_header.chunks():
        cache = {}
        for record in chunk.records():
            record_str = _build_record_xml(record, cache=cache)
            yield record_str.encode("utf8", "xmlcharrefreplace"), record


def evtx_template_readable_view(root_node, cache=None):
    """
    """
    if cache is None:
        cache = {}

    def rec(node, acc):
        if isinstance(node, EndOfStreamNode):
            pass  # intended
        elif isinstance(node, OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, AttributeNode):
                    acc.append(" ")
                    acc.append(child.attribute_name().string())
                    acc.append("=\"")
                    rec(child.attribute_value(), acc)
                    acc.append("\"")
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(node.tag_name())
            acc.append(">\n")
        elif isinstance(node, CloseStartElementNode):
            pass  # intended
        elif isinstance(node, CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, CloseElementNode):
            pass  # intended
        elif isinstance(node, ValueNode):
            acc.append(node.children()[0].string())
        elif isinstance(node, AttributeNode):
            pass  # intended
        elif isinstance(node, CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(node.cdata())
            acc.append("]]>")
        elif isinstance(node, EntityReferenceNode):
            acc.append(node.entity_reference())
        elif isinstance(node, ProcessingInstructionTargetNode):
            acc.append(node.processing_instruction_target())
        elif isinstance(node, ProcessingInstructionDataNode):
            acc.append(node.string())
        elif isinstance(node, TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, NormalSubstitutionNode):
            acc.append("[Normal Substitution(index=%d, type=%d)]" % \
                           (node.index(), node.type()))
        elif isinstance(node, ConditionalSubstitutionNode):
            acc.append("[Conditional Substitution(index=%d, type=%d)]" % \
                           (node.index(), node.type()))
        elif isinstance(node, StreamStartNode):
            pass  # intended

    acc = []
    template_instance = root_node.fast_template_instance()
    templ_off = template_instance.template_offset() + \
        template_instance._chunk.offset()
    if templ_off in cache:
        acc.append(cache[templ_off])
    else:
        node = TemplateNode(template_instance._buf, templ_off,
                            template_instance._chunk, template_instance)
        sub_acc = []
        for c in node.children():
            rec(c, sub_acc)
        sub_templ = "".join(sub_acc)
        cache[templ_off] = sub_templ
        acc.append(sub_templ)
    return "".join(acc)


class InvalidRecordException(ParseException):
    def __init__(self):
        super(InvalidRecordException, self).__init__(
            "Invalid record structure")


class Evtx(object):
    """
    A convenience class that makes it easy to open an
      EVTX file and start iterating the important structures.
    Note, this class must be used in a context statement
       (see the `with` keyword).
    Note, this class will mmap the target file, so ensure
      your platform supports this operation.
    """
    def __init__(self, filename):
        """
        @type filename:  str
        @param filename: A string that contains the path
          to the EVTX file to open.
        """
        self._filename = filename
        self._buf = None
        self._f = None
        self._fh = None

    def __enter__(self):
        self._f = open(self._filename, "rb")
        self._buf = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self._fh = FileHeader(self._buf, 0x0)
        return self

    def __exit__(self, type, value, traceback):
        self._buf.close()
        self._f.close()
        self._fh = None

    def ensure_contexted(func):
        """
        This decorator ensure that an instance of the
          Evtx class is used within a context statement.  That is,
          that the `with` statement is used, or `__enter__()`
          and `__exit__()` are called explicitly.
        """
        @wraps(func)
        def wrapped(self, *args, **kwargs):
            if self._buf is None:
                raise TypeError("An Evtx object must be used with"
                                " a context (see the `with` statement).")
            else:
                return func(self, *args, **kwargs)
        return wrapped

    @ensure_contexted
    def chunks(self):
        """
        Get each of the ChunkHeaders from within this EVTX file.

        @rtype generator of ChunkHeader
        @return A generator of ChunkHeaders from this EVTX file.
        """
        for chunk in self._fh.chunks():
            yield chunk

    @ensure_contexted
    def records(self):
        """
        Get each of the Records from within this EVTX file.

        @rtype generator of Record
        @return A generator of Records from this EVTX file.
        """
        for chunk in self.chunks():
            for record in chunk.records():
                yield record

    @ensure_contexted
    def get_record(self, record_num):
        """
        Get a Record by record number.

        @type record_num:  int
        @param record_num: The record number of the the record to fetch.
        @rtype Record or None
        @return The record request by record number, or None if
          the record is not found.
        """
        return self._fh.get_record(record_num)

    @ensure_contexted
    def get_file_header(self):
        return self._fh


class FileHeader(Block):
    def __init__(self, buf, offset):
        debug("FILE HEADER at %s." % (hex(offset)))
        super(FileHeader, self).__init__(buf, offset)
        self.declare_field("string", "magic", 0x0, length=8)
        self.declare_field("qword",  "oldest_chunk")
        self.declare_field("qword",  "current_chunk_number")
        self.declare_field("qword",  "next_record_number")
        self.declare_field("dword",  "header_size")
        self.declare_field("word",   "minor_version")
        self.declare_field("word",   "major_version")
        self.declare_field("word",   "header_chunk_size")
        self.declare_field("word",   "chunk_count")
        self.declare_field("binary", "unused1", length=0x4c)
        self.declare_field("dword",  "flags")
        self.declare_field("dword",  "checksum")

    def __repr__(self):
        return "FileHeader(buf=%r, offset=%r)" % (self._buf, self._offset)

    def __str__(self):
        return "FileHeader(offset=%s)" % (hex(self._offset))

    def check_magic(self):
        """
        @return A boolean that indicates if the first eight bytes of
          the FileHeader match the expected magic value.
        """
        return self.magic() == "ElfFile\x00"

    def calculate_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum off the first 0x78 bytes.
          This is consistent with the checksum stored by the FileHeader.
        """
        return binascii.crc32(self.unpack_binary(0, 0x78)) & 0xFFFFFFFF

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader
          successfully passes a set of heuristic checks that
          all EVTX FileHeaders should pass.
        """
        return self.check_magic() and \
            self.major_version() == 0x3 and \
            self.minor_version() == 0x1 and \
            self.header_chunk_size() == 0x1000 and \
            self.checksum() == self.calculate_checksum()

    def is_dirty(self):
        """
        @return A boolean that indicates that the log has been
          opened and was changed, though not all changes might be
          reflected in the file header.
        """
        return self.flags() & 0x1 == 0x1

    def is_full(self):
        """
        @return A boolean that indicates that the log
          has reached its maximum configured size and the retention
          policy in effect does not allow to reclaim a suitable amount
          of space from the oldest records and an event message could
          not be written to the log file.
        """
        return self.flags() & 0x2 == 0x2

    def first_chunk(self):
        """
        @return A ChunkHeader instance that is the first chunk
          in the log file, which is always found directly after
          the FileHeader.
        """
        ofs = self._offset + self.header_chunk_size()
        return ChunkHeader(self._buf, ofs)

    def current_chunk(self):
        """
        @return A ChunkHeader instance that is the current chunk
          indicated by the FileHeader.
        """
        ofs = self._offset + self.header_chunk_size()
        ofs += (self.current_chunk_number() * 0x10000)
        return ChunkHeader(self._buf, ofs)

    def chunks(self):
        """
        @return A generator that yields the chunks of the log file
          starting with the first chunk, which is always found directly
          after the FileHeader, and continuing to the end of the file.
        """
        ofs = self._offset + self.header_chunk_size()
        while ofs + 0x10000 <= len(self._buf):
            yield ChunkHeader(self._buf, ofs)
            ofs += 0x10000

    def get_record(self, record_num):
        """
        Get a Record by record number.

        @type record_num:  int
        @param record_num: The record number of the the record to fetch.
        @rtype Record or None
        @return The record request by record number, or None if the
          record is not found.
        """
        for chunk in self.chunks():
            first_record = chunk.log_first_record_number()
            last_record = chunk.log_last_record_number()
            if not (first_record <= record_num <= last_record):
                continue
            for record in chunk.records():
                if record.record_num() == record_num:
                    return record
        return None


class Template(object):
    def __init__(self, template_node):
        self._template_node = template_node
        self._xml = None

    def _load_xml(self):
        """
        TODO(wb): One day, nodes should generate format strings
          instead of the XML format made-up abomination.
        """
        if self._xml is not None:
            return
        matcher = "\[(?:Normal|Conditional) Substitution\(index=(\d+), type=\d+\)\]"
        self._xml = re.sub(matcher, "{\\1:}",
                           self._template_node.template_format().replace("{", "{{").replace("}", "}}"))

    def make_substitutions(self, substitutions):
        """

        @type substitutions: list of VariantTypeNode
        """
        self._load_xml()
        return self._xml.format(*map(lambda n: n.xml(), substitutions))

    def node(self):
        return self._template_node


class ChunkHeader(Block):
    def __init__(self, buf, offset):
        debug("CHUNK HEADER at %s." % (hex(offset)))
        super(ChunkHeader, self).__init__(buf, offset)
        self._strings = None
        self._templates = None

        self.declare_field("string", "magic", 0x0, length=8)
        self.declare_field("qword",  "file_first_record_number")
        self.declare_field("qword",  "file_last_record_number")
        self.declare_field("qword",  "log_first_record_number")
        self.declare_field("qword",  "log_last_record_number")
        self.declare_field("dword",  "header_size")
        self.declare_field("dword",  "last_record_offset")
        self.declare_field("dword",  "next_record_offset")
        self.declare_field("dword",  "data_checksum")
        self.declare_field("binary", "unused", length=0x44)
        self.declare_field("dword",  "header_checksum")

    def __repr__(self):
        return "ChunkHeader(buf=%r, offset=%r)" % (self._buf, self._offset)

    def __str__(self):
        return "ChunkHeader(offset=%s)" % (hex(self._offset))

    def check_magic(self):
        """
        @return A boolean that indicates if the first eight bytes of
          the ChunkHeader match the expected magic value.
        """
        return self.magic() == "ElfChnk\x00"

    def calculate_header_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum of the ChunkHeader fields.
        """
        data = self.unpack_binary(0x0, 0x78)
        data += self.unpack_binary(0x80, 0x180)
        return binascii.crc32(data) & 0xFFFFFFFF

    def calculate_data_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum of the Chunk data.
        """
        data = self.unpack_binary(0x200, self.next_record_offset() - 0x200)
        return binascii.crc32(data) & 0xFFFFFFFF

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader
          successfully passes a set of heuristic checks that
          all EVTX ChunkHeaders should pass.
        """
        return self.check_magic() and \
            self.calculate_header_checksum() == self.header_checksum() and \
            self.calculate_data_checksum() == self.data_checksum()

    def _load_strings(self):
        if self._strings is None:
            self._strings = {}
        for i in xrange(64):
            ofs = self.unpack_dword(0x80 + (i * 4))
            while ofs > 0:
                string_node = self.add_string(ofs)
                ofs = string_node.next_offset()

    def strings(self):
        """
        @return A dict(offset --> NameStringNode)
        """
        if not self._strings:
            self._load_strings()
        return self._strings

    def add_string(self, offset, parent=None):
        """
        @param offset An integer offset that is relative to the start of
          this chunk.
        @param parent (Optional) The parent of the newly created
           NameStringNode instance. (Default: this chunk).
        @return None
        """
        if self._strings is None:
            self._load_strings()
        string_node = NameStringNode(self._buf, self._offset + offset,
                                     self, parent or self)
        self._strings[offset] = string_node
        return string_node

    def _load_templates(self):
        """
        @return None
        """
        if self._templates is None:
            self._templates = {}
        for i in xrange(32):
            ofs = self.unpack_dword(0x180 + (i * 4))
            while ofs > 0:
                # unclear why these are found before the offset
                # this is a direct port from A.S.'s code
                token = self.unpack_byte(ofs - 10)
                pointer = self.unpack_dword(ofs - 4)
                if token != 0x0c or pointer != ofs:
                    warning("Unexpected token encountered")
                    ofs = 0
                    continue
                template = self.add_template(ofs)
                ofs = template.next_offset()

    def add_template(self, offset, parent=None):
        """
        @param offset An integer which contains the chunk-relative offset
           to a template to load into this Chunk.
        @param parent (Optional) The parent of the newly created
           TemplateNode instance. (Default: this chunk).
        @return Newly added TemplateNode instance.
        """
        if self._templates is None:
            self._load_templates()

        node = TemplateNode(self._buf, self._offset + offset,
                                self, parent or self)
        self._templates[offset] = node
        return node

    def templates(self):
        """
        @return A dict(offset --> Template) of all encountered
          templates in this Chunk.
        """
        if not self._templates:
            self._load_templates()
        return self._templates

    def first_record(self):
        return Record(self._buf, self._offset + 0x200, self)

    def records(self):
        record = self.first_record()
        while record._offset < self._offset + self.next_record_offset() and record.length() > 0:
            yield record
            try:
                record = Record(self._buf,
                                record._offset + record.length(),
                                self)
            except InvalidRecordException:
                pass


class Record(Block):
    def __init__(self, buf, offset, chunk):
        debug("Record at %s." % (hex(offset)))
        super(Record, self).__init__(buf, offset)
        self._chunk = chunk

        self.declare_field("dword", "magic", 0x0)  # 0x00002a2a
        self.declare_field("dword", "size")
        self.declare_field("qword", "record_num")
        self.declare_field("filetime", "timestamp")

        """if self.size() > 0x10000:
            raise InvalidRecordException()
        """

        self.declare_field("dword", "size2", self.size() - 4)

    def __repr__(self):
        return "Record(buf=%r, offset=%r)" % (self._buf, self._offset)

    def __str__(self):
        return "Record(offset=%s)" % (hex(self._offset))

    def root(self):
        return RootNode(self._buf, self._offset + 0x18, self._chunk, self)

    def length(self):
        return self.size()

    def verify(self):
        return self.size() == self.size2()

    def data(self):
        """
        Return the raw data block which makes up this record as a bytestring.

        @rtype str
        @return A string that is a copy of the buffer that makes
          up this record.
        """
        return self._buf[self.offset():self.offset() + self.size()]



config = conf.config
_replacement_patterns = {i: re.compile("\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % i) for i in
                         xrange(35)}

class EvtxLogs(common.AbstractWindowsCommand):

    """Extract Windows Event Logs (Vista/7/8/10 only)"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump log files')
        self.files_to_remove = []

    @staticmethod
    def is_valid_profile(profile):
        """This plugin is valid on Vista and later"""
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 6)

    def does_offset_seems_like_chunk_header(self, buf, offset):
        """
        Return True if the offset appears to be an EVTX Chunk header.
        Implementation note: Simply checks the magic header and size field for reasonable values.

        @type buf: bytestring
        @type offset: int
        @rtype boolean
        """
        EVTX_HEADER_MAGIC = "ElfChnk"

        try:
            if struct.unpack_from("<7s", buf, offset)[0] != EVTX_HEADER_MAGIC:
                return False
            if not (0x80 <= struct.unpack_from("<I", buf, offset + 0x28)[0] <= 0x200):
                return False
        except OverrunBufferException:
            return False
        return True

    def find_evtx_chunks(self, state, buf):
        """
        Scans the given data for valid EVTX chunk structures and adds the offsets
          to the State instance.

        @type state: State
        @type buf: bytestring
        @rtype: int
        @return: The number of chunks found and added to the State database.
        """

        EVTX_HEADER_MAGIC = "ElfChnk"

        num_chunks_found = 0
        index = buf.find(EVTX_HEADER_MAGIC)
        while index != -1:
            if self.does_offset_seems_like_chunk_header(buf, index):
                chunk = ChunkHeader(buf, index)
                if len(buf) - index < 0x10000:
                    logger.debug("%s\t%s" % ("CHUNK_BAD_SIZE", hex(index)))
                elif chunk.calculate_header_checksum() != chunk.header_checksum():
                    logger.debug("%s\t%s" % ("CHUNK_BAD_HEADER", hex(index)))
                elif chunk.calculate_data_checksum() != chunk.data_checksum():
                    logger.debug("%s\t%s" % ("CHUNK_BAD_DATA", hex(index)))
                else:
                    state.add_valid_chunk_offset(index)
                    num_chunks_found += 1
            index = buf.find(EVTX_HEADER_MAGIC, index + 1)
        return num_chunks_found

    def _make_replacement(self, template, index, substitution):
        """
        Makes a substitution given a template as a string.

        Implementation is a huge hack that depends on the
        brittle template_format() output.

        @type template: str
        @type index: int
        @type substitution: str
        @rtype: str
        """
        if index not in _replacement_patterns:
            from_pattern = re.compile("\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % index)
            _replacement_patterns[index] = from_pattern
        return _replacement_patterns[index].sub(substitution, template)


    def _get_complete_template(self, root, current_index=0):
        """
        Gets the template from a RootNode while resolving any
        nested templates and fixing up their indices.
        Depth first ordering/indexing.

        Implementation is a huge hack that depends on the
          brittle template_format() output.

        @type root: RootNode
        @type current_index: int
        @rtype: str
        """
        template = evtx_template_readable_view(root)  # TODO(wb): make sure this is working

        # walk through each substitution.
        # if its a normal node, continue
        # else its a subtemplate, and we count the number of substitutions _it_ has
        #   so that we can later fixup all the indices
        replacements = []
        for index, substitution in enumerate(root.substitutions()):
            # find all sub-templates
            if not isinstance(substitution, BXmlTypeNode):
                replacements.append(current_index + index)
                continue
            # TODO(wb): hack here accessing ._root
            subtemplate = self._get_complete_template(substitution._root,
                                                 current_index=current_index + index)
            replacements.append(subtemplate)
            current_index += subtemplate.count("Substitution(index=")
        replacements.reverse()

        # now walk through all the indices and fix them up depth-first
        for i, replacement in enumerate(replacements):
            index = len(replacements) - i - 1
            if isinstance(replacement, int):
                # fixup index
                from_pattern = "index=%d," % index
                to_pattern = "index=%d," % replacement
                template = template.replace(from_pattern, to_pattern)
            if isinstance(replacement, basestring):
                # insert sub-template
                template = self._make_replacement(template, index, replacement)
        return template

    def get_template(self, record, record_xml):
        """
        Given a complete Record, parse out the nodes that make up the Template
          and return it as a Template.

        @type record: Record
        @type record_xml: str
        @rtype: Template
        """
        template = self._get_complete_template(record.root())
        return Template(int(get_eid(record_xml)), template)

    def extract_chunk(self, buf, offset, state, templates):
        """
        Parse an EVTX chunk
          updating the State with new valid records, and
          extracting the templates into a TemplateDatabase.

        @sideeffect: parameter `templates`
        @sideeffect: parameter `state`

        @type buf: bytestring
        @type offset: int
        @type state: State
        @type templates: TemplateDatabase
        """

        chunk = ChunkHeader(buf, offset)

        xml = []
        cache = {}
        for record in chunk.records():
            try:
                offset = record.offset()
                record_xml = evtx_record_xml_view(record, cache=cache)
                eid = get_eid(record_xml)

                state.add_valid_record(offset, eid, record_xml)

                template = get_template(record, record_xml)
                templates.add_template(template)
            except UnicodeEncodeError:
                continue
            except UnicodeDecodeError:
                continue
            except InvalidRecordException:
                continue
            except Exception as e:
                continue


    def extract_valid_evtx_records_and_templates(self, state, templates, buf):
        for i, chunk_offset in enumerate(state.get_valid_chunk_offsets()):
            self.extract_chunk(buf, chunk_offset, state, templates)

    def does_offset_seems_like_record(self, buf, offset):
        """
        Return True if the offset appears to be an EVTX record.

        @type buf: bytestring
        @type offset: int
        @rtype boolean
        """
        try:
            magic, size = struct.unpack_from("<II", buf, offset)
            if magic != 0x00002a2a:
                return False
            if not (0x30 <= size <= 0x10000):
                return False
            try:
                size2 = struct.unpack_from("<I", buf, offset + size - 4)[0]
            except struct.error:
                return False
            if size != size2:
                return False
        except OverrunBufferException:
            return False
        return True


    def find_lost_evtx_records(self, buf, ranges):
        """
        Generates offsets of apparent EVTX records from the given buffer
          that fall within the given ranges.

        @type buf: bytestring
        @type ranges: list of (int, int)
        @rtype: generator of int
        """

        EVTX_RECORD_MAGIC = "\x2a\x2a\x00\x00"

        for range_ in ranges:
            start, end = range_
            index = buf.find(EVTX_RECORD_MAGIC, start, end)
            while index != -1:
                if self.does_offset_seems_like_record(buf, index):
                    yield index
                index = buf.find(EVTX_RECORD_MAGIC, index + 1, end)

    def calculate(self):
        records = []

        image_path = (config.LOCATION).replace('file://', '')
        image_path = image_path.replace('%28', '(')
        image_path = image_path.replace('%29', ')')

        with State("default") as state:
            self.files_to_remove.append(os.path.realpath(state._filename))
            with Mmap(image_path) as buf:
                num_chunks_found = self.find_evtx_chunks(state, buf)
            print("# Found %d valid chunks." % num_chunks_found)

        with State("default") as state:
            with TemplateDatabase("default.db") as templates:
                self.files_to_remove.append(os.path.realpath(templates._filename))
                with Mmap(image_path) as buf:
                    num_templates_before = templates.get_number_of_templates()
                    num_valid_records_before = len(state.get_valid_records())
                    self.extract_valid_evtx_records_and_templates(state, templates, buf)
                    num_templates_after = templates.get_number_of_templates()
                    num_valid_records_after = len(state.get_valid_records())
                    print("# Found %d new templates." % (num_templates_after - num_templates_before))
                    print("# Found %d new valid records." % (num_valid_records_after - num_valid_records_before))

        with State("default") as state:
            ranges = []
            range_start = 0
            for chunk_offset in state.get_valid_chunk_offsets():
                ranges.append((range_start, chunk_offset))
                range_start = chunk_offset + 0x10000
            ranges.append((range_start, os.stat(image_path).st_size))  # from here to end of file

            with Mmap(image_path) as buf:
                num_potential_records_before = len(state.get_potential_record_offsets())
                for offset in self.find_lost_evtx_records(buf, ranges):
                    state.add_potential_record_offset(offset)
                num_potential_records_after = len(state.get_potential_record_offsets())
                print("# Found %d potential EVTX records." % (num_potential_records_after - num_potential_records_before))

        with State("default") as state:
            if len(state.get_valid_records()) == 0:
                print ("# No valid records found.")

            for event in state.get_valid_records():
                records.append(event["xml"])

        return records

    def render_text(self, outfd, data):
        name = 'evtx-output.txt'
        fh = open(os.path.join(self._config.DUMP_DIR, name), 'wb')
        for record in data:
            fh.write(str(record))
        fh.close()
        outfd.write('Parsed data sent to {0}\n'.format(name))

        # Delete temp files made during the extraction process. If you don't
        # delete these, the plugin will not work when moving between different
        # images.
        for f in self.files_to_remove:
            os.remove(f)
