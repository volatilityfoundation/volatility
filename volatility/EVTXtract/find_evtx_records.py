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
import os
import logging
import struct

from Evtx.BinaryParser import OverrunBufferException
from Progress import NullProgress
from State import State
from recovery_utils import Mmap, do_common_argparse_config


logger = logging.getLogger("find_evtx_records")
EVTX_RECORD_MAGIC = "\x2a\x2a\x00\x00"


def does_offset_seems_like_record(buf, offset):
    """
    Return True if the offset appears to be an EVTX record.

    @type buf: bytestring
    @type offset: int
    @rtype boolean
    """
    logger.debug("Record header check: Checking for a record at %s", hex(offset))
    try:
        magic, size = struct.unpack_from("<II", buf, offset)
        if magic != 0x00002a2a:
            logger.debug("Record header check: Failed: Bad magic")
            return False
        if not (0x30 <= size <= 0x10000):
            logger.debug("Record header check: Failed: Bad size")
            return False
        try:
            size2 = struct.unpack_from("<I", buf, offset + size - 4)[0]
        except struct.error:
            logger.debug("Record header check: Failed: Bad buffer size")
            return False
        if size != size2:
            logger.debug("Record header check: Failed: Bad size2 (%s vs %s)", hex(size), hex(size2))
            return False
    except OverrunBufferException:
        logger.debug("Record header check: Failed: Bad buffer size")
        return False
    logger.debug("Record header check: Success")
    return True


def find_lost_evtx_records(buf, ranges, progress_class=NullProgress):
    """
    Generates offsets of apparent EVTX records from the given buffer
      that fall within the given ranges.

    @type buf: bytestring
    @type ranges: list of (int, int)
    @rtype: generator of int
    """
    progress = progress_class(len(buf))
    for range_ in ranges:
        start, end = range_
        logger.debug("Searching for records in the range (%s, %s)",
                     hex(start), hex(end))
        index = buf.find(EVTX_RECORD_MAGIC, start, end)
        while index != -1:
            progress.set_current(index)
            if does_offset_seems_like_record(buf, index):
                yield index
            index = buf.find(EVTX_RECORD_MAGIC, index + 1, end)
        progress.set_complete()


def main():
    args = do_common_argparse_config("Find offsets of EVTX records.")

    with State(args.project_json) as state:
        ranges = []
        range_start = 0
        for chunk_offset in state.get_valid_chunk_offsets():
            ranges.append((range_start, chunk_offset))
            range_start = chunk_offset + 0x10000
        ranges.append((range_start, os.stat(args.image).st_size))  # from here to end of file

        with Mmap(args.image) as buf:
            num_potential_records_before = len(state.get_potential_record_offsets())
            for offset in find_lost_evtx_records(buf, ranges, progress_class=args.progress_class):
                state.add_potential_record_offset(offset)
            num_potential_records_after = len(state.get_potential_record_offsets())
            print("# Found %d potential EVTX records." % (num_potential_records_after - num_potential_records_before))


if __name__ == "__main__":
    main()
