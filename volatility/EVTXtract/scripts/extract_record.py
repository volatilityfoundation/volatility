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
#   Version v.0.1
import sys

from Evtx.Evtx import Evtx


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Write the raw data for a EVTX record to STDOUT")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("record", type=int,
                        help="The record number of the record to extract")
    args = parser.parse_args()

    with Evtx(args.evtx) as evtx:
        record = evtx.get_record(args.record)
        if record is None:
            raise RuntimeError("Cannot find the record specified.")
        sys.stdout.write(record.data())


if __name__ == "__main__":
    main()
