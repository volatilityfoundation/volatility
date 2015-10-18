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
import logging
import struct

from Evtx.Evtx import ChunkHeader
from Evtx.BinaryParser import OverrunBufferException
from Progress import NullProgress
from State import State
from recovery_utils import Mmap, do_common_argparse_config

EVTX_HEADER_MAGIC = "ElfChnk"
logger = logging.getLogger("find_evtx_chunks")


def does_offset_seems_like_chunk_header(buf, offset):
    """
    Return True if the offset appears to be an EVTX Chunk header.
    Implementation note: Simply checks the magic header and size field for reasonable values.

    @type buf: bytestring
    @type offset: int
    @rtype boolean
    """
    logger.debug("Chunk header check: Checking for a chunk at %s", hex(offset))
    try:
        if struct.unpack_from("<7s", buf, offset)[0] != EVTX_HEADER_MAGIC:
            logger.debug("Chunk header check: Failed: Bad magic")
            return False
        if not (0x80 <= struct.unpack_from("<I", buf, offset + 0x28)[0] <= 0x200):
            logger.debug("Chunk header check: Failed: Bad size")
            return False
    except OverrunBufferException:
        logger.debug("Chunk header check: Failed: Bad buffer size")
        return False
    logger.debug("Chunk header check: Success")
    return True


def find_evtx_chunks(state, buf, progress_class=NullProgress):
    """
    Scans the given data for valid EVTX chunk structures and adds the offsets
      to the State instance.

    @type state: State
    @type buf: bytestring
    @rtype: int
    @return: The number of chunks found and added to the State database.
    """
    progress = progress_class(len(buf))
    num_chunks_found = 0
    index = buf.find(EVTX_HEADER_MAGIC)
    while index != -1:
        progress.set_current(index)
        if does_offset_seems_like_chunk_header(buf, index):
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
    progress.set_complete()
    return num_chunks_found


def main():
    args = do_common_argparse_config("Find valid EVTX chunks.")

    with State(args.project_json) as state:
        with Mmap(args.image) as buf:
            num_chunks_found = find_evtx_chunks(state, buf, progress_class=args.progress_class)
    print("# Found %d valid chunks." % num_chunks_found)


if __name__ == "__main__":
    main()
