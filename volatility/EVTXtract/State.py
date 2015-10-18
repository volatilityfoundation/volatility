#!/bin/python
#    This file is part of recover-evtx.
#
#   Copyright 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
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
import hashlib
import json
import os
import logging
import traceback
from recovery_utils import exists

CURRENT_VERSION = 1
GENERATOR = "recover-evtx"
logger = logging.getLogger("state")


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
