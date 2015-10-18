#!/bin/python
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
#   Version v0.1


import sys
import binascii
import mmap
import contextlib

from Evtx.Evtx import FileHeader


def main():
    with open(sys.argv[1], 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)

            print "Information from file header:"
            print "Format version  : %d.%d" % (fh.major_version(),
                                               fh.minor_version())
            print "Flags           : 0x%08x" % (fh.flags())
            dirty_string = "clean"
            if fh.is_dirty():
                dirty_string = "dirty"
            print "File is         : %s" % (dirty_string)
            full_string = "no"
            if fh.is_full():
                full_string = "yes"
            print "Log is full     : %s" % (full_string)
            print "Current chunk   : %d of %d" % (fh.current_chunk_number(),
                                                  fh.chunk_count())
            print "Oldest chunk    : %d" % (fh.oldest_chunk() + 1)
            print "Next record#    : %d" % (fh.next_record_number())
            checksum_string = "fail"
            if fh.calculate_checksum() == fh.checksum():
                checksum_string = "pass"
            print "Check sum       : %s" % (checksum_string)
            print ""

            if fh.is_dirty():
                chunk_count = sum([1 for c in fh.chunks() if c.verify()])

                last_chunk = None
                for chunk in fh.chunks():
                    if not chunk.verify():
                        continue
                    last_chunk = chunk
                next_record_num = last_chunk.log_last_record_number() + 1

                print "Suspected updated header values (header is dirty):"
                print "Current chunk   : %d of %d" % (chunk_count,
                                                      chunk_count)
                print "Next record#    : %d" % (next_record_num)
                print ""

            print "Information from chunks:"
            print "  Chunk file (first/last)     log (first/last)      Header Data"
            print "- ----- --------------------- --------------------- ------ ------"
            for (i, chunk) in enumerate(fh.chunks(), 1):
                note_string = " "
                if i == fh.current_chunk_number() + 1:
                    note_string = "*"
                elif i == fh.oldest_chunk() + 1:
                    note_string = ">"

                if not chunk.check_magic():
                    if chunk.magic() == "\x00\x00\x00\x00\x00\x00\x00\x00":
                        print "%s  %4d     [EMPTY]" % (note_string, i)
                    else:
                        print "%s  %4d   [INVALID]" % (note_string, i)
                    continue

                header_checksum_string = "fail"
                if chunk.calculate_header_checksum() == chunk.header_checksum():
                    header_checksum_string = "pass"

                data_checksum_string = "fail"
                if chunk.calculate_data_checksum() == chunk.data_checksum():
                    data_checksum_string = "pass"

                print "%s  %4d   %8d  %8d    %8d  %8d   %s   %s" % \
                    (note_string,
                     i,
                     chunk.file_first_record_number(),
                     chunk.file_last_record_number(),
                     chunk.log_first_record_number(),
                     chunk.log_last_record_number(),
                     header_checksum_string,
                     data_checksum_string)

if __name__ == "__main__":
    main()
