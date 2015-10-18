#!/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2015 Willi Ballenthin <william.ballenthin@mandiant.com>
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
import mmap
import sys
import contextlib

import argparse

from Evtx.Evtx import FileHeader


def main():
    parser = argparse.ArgumentParser(
        description="Dump the slack space of an EVTX file.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX event log file")
    args = parser.parse_args()

    with open(args.evtx, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            for chunk in fh.chunks():
                chunk_start = chunk.offset()
                last_allocated_offset = chunk_start
                for record in chunk.records():
                    last_allocated_offset = record.offset() + record.size()
                sys.stdout.write(buf[last_allocated_offset:chunk_start + 0x10000])


if __name__ == "__main__":
    main()
