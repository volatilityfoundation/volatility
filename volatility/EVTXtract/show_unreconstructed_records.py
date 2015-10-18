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
from State import State
from recovery_utils import do_common_argparse_config


_sub_types = {
    0x00: "Null",
    0x01: "WideString",
    0x02: "ASCIIString",
    0x03: "SignedByte",
    0x04: "UnsignedByte",
    0x05: "SignedWord",
    0x06: "UnsignedWord",
    0x07: "SignedDword",
    0x08: "UnsignedDword",
    0x09: "SignedQword",
    0x0A: "UnsignedQword",
    0x0B: "Float",
    0x0C: "Double",
    0x0D: "Boolean",
    0x0E: "Binary",
    0x0F: "GUID",
    0x10: "Size",
    0x11: "Filetime",
    0x12: "Systemtime",
    0x13: "SID",
    0x14: "Hex32",
    0x15: "Hex64",
    0x21: "BXml",
    0x81: "WstringArray",
}


def format_unreconstructed_record(record, line_prefix=""):
    """
    @type record: dict
    @param record: A dict that contains the following data
      "offset": int,
      "substitutions": list of (int, str)
      "reason": str
    """
    ret = ["%sUNRECONSTRUCTED RECORD" % line_prefix,
           "%sOffset: %d" % (line_prefix, record["offset"]),
           "%sReason: %s" % (line_prefix, record["reason"]),
           "%sSubstitutions:" % (line_prefix)]
    for sub_type, sub_value in record["substitutions"]:
        out_type, out_value = _sub_types.get(sub_type, "UnknownType"), str(sub_value)
        ret.append("%s  Substitution: %s  %s" % (line_prefix, out_type, out_value))
    return "\n".join(ret)


def main():
    args = do_common_argparse_config("Show unreconstructed EVTX records.")
    with State(args.project_json) as state:
        if len(state.get_unreconstructed_records()) == 0:
            print ("# No unreconstructed records found.")
        for event in state.get_unreconstructed_records():
            print(format_unreconstructed_record(event))


if __name__ == "__main__":
    main()

