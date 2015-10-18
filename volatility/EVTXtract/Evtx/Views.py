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
from Nodes import RootNode
from Nodes import TemplateNode
from Nodes import EndOfStreamNode
from Nodes import OpenStartElementNode
from Nodes import CloseStartElementNode
from Nodes import CloseEmptyElementNode
from Nodes import CloseElementNode
from Nodes import ValueNode
from Nodes import AttributeNode
from Nodes import CDataSectionNode
from Nodes import EntityReferenceNode
from Nodes import ProcessingInstructionTargetNode
from Nodes import ProcessingInstructionDataNode
from Nodes import TemplateInstanceNode
from Nodes import NormalSubstitutionNode
from Nodes import ConditionalSubstitutionNode
from Nodes import StreamStartNode
from xml.sax.saxutils import escape as xml_sax_escape

class UnexpectedElementException(Exception):
    def __init__(self, msg):
        super(UnexpectedElementException, self).__init__(msg)


def _make_template_xml_view(root_node, cache=None):
    """
    Given a RootNode, parse only the template/children
      and not the substitutions.

    Note, the cache should be local to the Evtx.Chunk.
      Do not share caches across Chunks.

    @type root_node: Nodes.RootNode
    @type cache: dict of {int: TemplateNode}
    @rtype: str
    """
    if cache is None:
        cache = {}

    def escape_format_chars(s):
        return s.replace("{", "{{").replace("}", "}}")

    def rec(node, acc):
        if isinstance(node, EndOfStreamNode):
            pass  # intended
        elif isinstance(node, OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, AttributeNode):
                    acc.append(" ")
                    acc.append(child.attribute_name().string())
                    acc.append("=\"")
                    rec(child.attribute_value(), acc)
                    acc.append("\"")
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(node.tag_name())
            acc.append(">\n")
        elif isinstance(node, CloseStartElementNode):
            pass  # intended
        elif isinstance(node, CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, CloseElementNode):
            pass  # intended
        elif isinstance(node, ValueNode):
            acc.append(escape_format_chars(node.children()[0].string()))
        elif isinstance(node, AttributeNode):
            pass  # intended
        elif isinstance(node, CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(node.cdata())
            acc.append("]]>")
        elif isinstance(node, EntityReferenceNode):
            acc.append(node.entity_reference())
        elif isinstance(node, ProcessingInstructionTargetNode):
            acc.append(node.processing_instruction_target())
        elif isinstance(node, ProcessingInstructionDataNode):
            acc.append(node.string())
        elif isinstance(node, TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, NormalSubstitutionNode):
            acc.append("{")
            acc.append("%d" % (node.index()))
            acc.append("}")
        elif isinstance(node, ConditionalSubstitutionNode):
            acc.append("{")
            acc.append("%d" % (node.index()))
            acc.append("}")
        elif isinstance(node, StreamStartNode):
            pass  # intended

    acc = []
    template_instance = root_node.fast_template_instance()
    templ_off = template_instance.template_offset() + \
        template_instance._chunk.offset()
    if templ_off in cache:
        acc.append(cache[templ_off])
    else:
        node = TemplateNode(template_instance._buf, templ_off,
                            template_instance._chunk, template_instance)
        sub_acc = []
        for c in node.children():
            rec(c, sub_acc)
        sub_templ = "".join(sub_acc)
        cache[templ_off] = sub_templ
        acc.append(sub_templ)
    return "".join(acc)


def _build_record_xml(record, cache=None):
    """
    Note, the cache should be local to the Evtx.Chunk.
      Do not share caches across Chunks.

    @type record: Evtx.Record
    @type cache: dict of {int: TemplateNode}
    @rtype: str
    """
    if cache is None:
        cache = {}

    def rec(root_node):
        f = _make_template_xml_view(root_node, cache=cache)
        subs_strs = []
        for sub in root_node.fast_substitutions():
            if isinstance(sub, basestring):
                subs_strs.append((xml_sax_escape(sub, {'"': "&quot;"})).encode("ascii", "xmlcharrefreplace"))
            elif isinstance(sub, RootNode):
                subs_strs.append(rec(sub))
            elif sub is None:
                subs_strs.append("")
            else:
                subs_strs.append(str(sub))
        return f.format(*subs_strs)
    xml = rec(record.root())
    return xml


def evtx_record_xml_view(record, cache=None):
    """
    Generate an UTF-8 XML representation of an EVTX record.

    Note, the cache should be local to the Evtx.Chunk.
      Do not share caches across Chunks.

    @type record: Evtx.Record
    @type cache: dict of {int: TemplateNode}
    @rtype: str
    """
    if cache is None:
        cache = {}
    return _build_record_xml(record, cache=cache).encode("utf8", "xmlcharrefreplace")


def evtx_chunk_xml_view(chunk):
    """
    Generate UTF-8 XML representations of the records in an EVTX chunk.

    Does not include the XML <?xml... header.
    Records are ordered by chunk.records()

    @type chunk: Evtx.Chunk
    @rtype: generator of str, Evtx.Record
    """
    cache = {}
    for record in chunk.records():
        record_str = _build_record_xml(record, cache=cache)
        yield record_str.encode("utf8", "xmlcharrefreplace"), record


def evtx_file_xml_view(file_header):
    """
    Generate UTF-8 XML representations of the records in an EVTX file.

    Does not include the XML <?xml... header.
    Records are ordered by file_header.chunks(), and then by chunk.records()

    @type file_header: Evtx.FileHeader
    @rtype: generator of str, Evtx.Record
    """
    for chunk in file_header.chunks():
        cache = {}
        for record in chunk.records():
            record_str = _build_record_xml(record, cache=cache)
            yield record_str.encode("utf8", "xmlcharrefreplace"), record


def evtx_template_readable_view(root_node, cache=None):
    """
    """
    if cache is None:
        cache = {}

    def rec(node, acc):
        if isinstance(node, EndOfStreamNode):
            pass  # intended
        elif isinstance(node, OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, AttributeNode):
                    acc.append(" ")
                    acc.append(child.attribute_name().string())
                    acc.append("=\"")
                    rec(child.attribute_value(), acc)
                    acc.append("\"")
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(node.tag_name())
            acc.append(">\n")
        elif isinstance(node, CloseStartElementNode):
            pass  # intended
        elif isinstance(node, CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, CloseElementNode):
            pass  # intended
        elif isinstance(node, ValueNode):
            acc.append(node.children()[0].string())
        elif isinstance(node, AttributeNode):
            pass  # intended
        elif isinstance(node, CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(node.cdata())
            acc.append("]]>")
        elif isinstance(node, EntityReferenceNode):
            acc.append(node.entity_reference())
        elif isinstance(node, ProcessingInstructionTargetNode):
            acc.append(node.processing_instruction_target())
        elif isinstance(node, ProcessingInstructionDataNode):
            acc.append(node.string())
        elif isinstance(node, TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, NormalSubstitutionNode):
            acc.append("[Normal Substitution(index=%d, type=%d)]" % \
                           (node.index(), node.type()))
        elif isinstance(node, ConditionalSubstitutionNode):
            acc.append("[Conditional Substitution(index=%d, type=%d)]" % \
                           (node.index(), node.type()))
        elif isinstance(node, StreamStartNode):
            pass  # intended

    acc = []
    template_instance = root_node.fast_template_instance()
    templ_off = template_instance.template_offset() + \
        template_instance._chunk.offset()
    if templ_off in cache:
        acc.append(cache[templ_off])
    else:
        node = TemplateNode(template_instance._buf, templ_off,
                            template_instance._chunk, template_instance)
        sub_acc = []
        for c in node.children():
            rec(c, sub_acc)
        sub_templ = "".join(sub_acc)
        cache[templ_off] = sub_templ
        acc.append(sub_templ)
    return "".join(acc)

