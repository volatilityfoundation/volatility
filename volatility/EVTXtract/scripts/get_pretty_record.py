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
import re
import xml.dom.minidom as minidom
from xml.parsers.expat import ExpatError

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_record_xml_view


def prettify_xml(xml_string):
    """
    @type xml_string: str
    """
    text_re = re.compile('>\n\s+([^<>\s].*?)\n\s+</', re.DOTALL)
    s = minidom.parseString(xml_string).toprettyxml()
    s = text_re.sub('>\g<1></', s)
    ret = ""
    for line in s.split("\n"):
        line = line.rstrip("\r\t ")
        ret += line
        if len(line) > 0:
            ret += "\n"
    return ret


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract a single EVTX record and pretty print it.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("record", type=int,
                        help="The record number of the record to extract")
    args = parser.parse_args()

    with Evtx(args.evtx) as evtx:
        record = evtx.get_record(args.record)
        if record is None:
            raise RuntimeError("Cannot find the record specified.")

        try:
            print prettify_xml("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>\n%s" % evtx_record_xml_view(record))
        except ExpatError as e:
            print "Exception: "
            print repr(e)
            print ""
            print ""
            print "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>\n%s" % evtx_record_xml_view(record)



if __name__ == "__main__":
    main()

