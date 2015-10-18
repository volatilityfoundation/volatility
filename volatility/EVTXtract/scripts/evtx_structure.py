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
import mmap
import contextlib

import argparse

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
from Evtx.Nodes import RootNode
from Evtx.Nodes import BXmlTypeNode
from Evtx.Nodes import AttributeNode
from Evtx.Nodes import VariantTypeNode
from Evtx.Nodes import TemplateInstanceNode
from Evtx.Nodes import OpenStartElementNode


class EvtxFormatter(object):
    def __init__(self):
        super(EvtxFormatter, self).__init__()
        self._indent_stack = []
        self._indent_unit = "  "

    def _indent(self):
        self._indent_stack.append(self._indent_unit)

    def _dedent(self):
        if len(self._indent_stack) > 0:
            self._indent_stack = self._indent_stack[:-1]

    def save_indent(self):
        return self._indent_stack[:]

    def restore_indent(self, indent):
        self._indent_stack = indent

    def _l(self, s):
        return "".join(self._indent_stack) + s

    def format_header(self, fh):
        yield self._l("File header")
        self._indent()
        yield self._l("magic: %s" % (fh.magic()))
        for num_field in [
                "oldest_chunk",
                "current_chunk_number",
                "next_record_number",
                "header_size",
                "minor_version",
                "major_version",
                "header_chunk_size",
                "chunk_count",
                "flags",
                "checksum"]:
            yield self._l("%s: %s" % (num_field, hex(getattr(fh, num_field)())))

        yield self._l("verify: %s" % (fh.verify()))
        yield self._l("dirty: %s" % (fh.is_dirty()))
        yield self._l("full: %s" % (fh.is_full()))

        for chunk in fh.chunks():
            for line in self.format_chunk(chunk):
                yield line
        self._dedent()

    def format_chunk(self, chunk):
        yield self._l("Chunk")
        self._indent()
        yield self._l("offset: %s" % (hex(chunk.offset())))
        yield self._l("magic: %s" % (chunk.magic()))

        for num_field in [
                "file_first_record_number",
                "file_last_record_number",
                "log_first_record_number",
                "log_last_record_number",
                "header_size",
                "last_record_offset",
                "next_record_offset",
                "data_checksum",
                "header_checksum"]:
            yield self._l("%s: %s" % (num_field, hex(getattr(chunk, num_field)())))

        yield self._l("verify: %s" % (chunk.verify()))
        yield self._l("templates: %d" % (len(chunk.templates())))

        for record in chunk.records():
            for line in self.format_record(record):
                yield line
        self._dedent()

    def format_record(self, record):
        yield self._l("Record")
        self._indent()
        yield self._l("offset: %s" % (hex(record.offset())))
        yield self._l("magic: %s" % (hex(record.magic())))
        yield self._l("size: %s" % (hex(record.size())))
        yield self._l("number: %s" % (hex(record.record_num())))
        yield self._l("timestamp: %s" % (record.timestamp()))
        yield self._l("verify: %s" % (record.verify()))

        try:
            s = self.save_indent()
            for line in self.format_node(record, record.root()):
                yield line
        except Exception as e:
            self.restore_indent(s)
            yield "ERROR: " + str(e)
        self._dedent()

    def _format_node_name(self, record, node, extra=None):
        """
        note: this doesn't yield, it returns
        """
        line = ""
        if extra is not None:
            line = "%s(offset=%s, %s)" % (node.__class__.__name__, hex(node.offset() - record.offset()), extra)
        else:
            line = "%s(offset=%s)" % (node.__class__.__name__, hex(node.offset() - record.offset()))

        if isinstance(node, VariantTypeNode):
            line += " --> %s" % (node.string())
        if isinstance(node, OpenStartElementNode):
            line += " --> %s" % (node.tag_name())
        if isinstance(node, AttributeNode):
            line += " --> %s" % (node.attribute_name().string())
        return line

    def format_node(self, record, node):
        extra = None
        if isinstance(node, TemplateInstanceNode) and node.is_resident_template():
            extra = "resident=True, length=%s" % (hex(node.template().data_length()))
        elif isinstance(node, TemplateInstanceNode):
            extra = "resident=False"
        yield self._l(self._format_node_name(record, node, extra=extra))

        if isinstance(node, BXmlTypeNode):
            self._indent()
            for line in self.format_node(record, node._root):
                yield line
            self._dedent()
        elif isinstance(node, TemplateInstanceNode) and node.is_resident_template():
            self._indent()
            for line in self.format_node(record, node.template()):
                yield line
            self._dedent()

        self._indent()
        for child in node.children():
            for line in self.format_node(record, child):
                yield line
        self._dedent()

        if isinstance(node, RootNode):
            ofs = node.tag_and_children_length()
            yield self._l("Substitutions(offset=%s)" % (hex(node.offset() - record.offset() + ofs)))
            self._indent()

            for sub in node.substitutions():
                for line in self.format_node(record, sub):
                    yield line
            self._dedent()


def main():
    parser = argparse.ArgumentParser(
        description="Dump the structure of an EVTX file.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX event log file")
    args = parser.parse_args()

    with open(args.evtx, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            formatter = EvtxFormatter()
            for line in formatter.format_header(fh):
                print(line)


if __name__ == "__main__":
    main()
