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
import re
import logging

# TODO(wb): fallback to standard xml parser
from lxml import etree
import mmap
from Progress import NullProgress, ProgressBarProgress


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


def do_common_argparse_config(description):
    """
    Return an object with at least the following fields:
      verbose: boolean
      vverbose: boolean
      progress: boolean
      image: str
      project_name: str
      template_db_name: str
      progress_class: Progress class
      project_json: str
      templates_json: str
    Also sets the logging config to the appropriate level given .verbose and .vverbose
    """
    import argparse
    parser = argparse.ArgumentParser(
        description=description)
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging.")
    parser.add_argument("--vverbose", action="store_true",
                        help="Enable verbose debug logging.")
    parser.add_argument("--progress", action="store_true",
                        help="Enable a progress bar (probably shouldn't be used with --verbose")
    parser.add_argument("image", type=str,
                        help="Path to the image file")
    parser.add_argument("project_name", type=str, nargs="?", default="default")
    parser.add_argument("template_db_name", type=str, nargs="?", default="default")
    args = parser.parse_args()

    has_some_logger_config = False
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        has_some_logger_config = True
    if args.vverbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        has_some_logger_config = True
    if not has_some_logger_config:
        logging.basicConfig(level=logging.WARN, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    args.progress_class = NullProgress
    if args.progress:
        args.progress_class = ProgressBarProgress

    args.project_json = args.project_name + ".json"

    # if the user supplies an explicit project name, but no template db name, use the
    #   project name as the basename for the template db
    if args.project_name != "default" and args.template_db_name == "default":
        args.template_db_name = args.project_name

    if not args.template_db_name.endswith(".db"):
        args.templates_json = args.template_db_name + ".db.json"
    else:
        args.templates_json = args.template_db_name + ".json"

    return args

