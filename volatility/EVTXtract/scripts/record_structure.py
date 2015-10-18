from Evtx.Evtx import Evtx
from Evtx.Nodes import RootNode
from Evtx.Nodes import BXmlTypeNode
from Evtx.Nodes import TemplateInstanceNode
from Evtx.Nodes import VariantTypeNode
from Evtx.BinaryParser import hex_dump
from Evtx.Views import evtx_record_xml_view


def describe_root(record, root, indent=0, suppress_values=False):
    """
    @type record: Record
    @type indent: int
    @rtype: None
    """
    def format_node(n, extra=None, indent=0):
        """
        Depends on closure over `record` and `suppress_values`.
        @type n: BXmlNode
        @type extra: str
        @rtype: str
        """
        ret = ""
        if extra is not None:
            ret = "%s%s(offset=%s, %s)" % \
                   ("  " * indent, n.__class__.__name__, hex(n.offset() - record.offset()), extra)
        else:
            ret = "%s%s(offset=%s)" % \
                   ("  " * indent, n.__class__.__name__, hex(n.offset() - record.offset()))

        if not suppress_values and isinstance(n, VariantTypeNode):
            ret += " --> %s" % (n.string())
            if isinstance(n, BXmlTypeNode):
                ret += "\n"
                ret += describe_root(record, n._root, indent=indent + 1)

        return ret

    def rec(node, indent=0):
        """
        @type node: BXmlNode
        @type indent: int
        @rtype: str
        """
        ret = ""
        if isinstance(node, TemplateInstanceNode):
            if node.is_resident_template():
                ret += "%s\n" % (format_node(node, extra="resident=True, length=%s" % (hex(node.template().data_length())), indent=indent))
                ret += rec(node.template(), indent=indent + 1)
            else:
                ret += "%s\n" % (format_node(node, extra="resident=False", indent=indent))
        else:
            ret += "%s\n" % (format_node(node, indent=indent))

        for child in node.children():
            ret += rec(child, indent=indent + 1)
        if isinstance(node, RootNode):
            ofs = node.tag_and_children_length()
            ret += "%sSubstitutions(offset=%s)\n" % ("  " * (indent + 1),
                                                     hex(node.offset() - record.offset() + ofs))
            for sub in node.substitutions():
                ret += "%s\n" % (format_node(sub, indent=indent + 2))
        return ret

    ret = ""
    ret += rec(root, indent=indent)
    return ret


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Pretty print the binary structure of an EVTX record.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("record", type=int,
                        help="Record number")
    parser.add_argument("--suppress_values", action="store_true",
                        help="Do not print the values of substitutions.")
    args = parser.parse_args()

    with Evtx(args.evtx) as evtx:
        print hex_dump(evtx.get_record(args.record).data())

        print("record(absolute_offset=%s)" % \
                  (evtx.get_record(args.record).offset()))
        print describe_root(evtx.get_record(args.record),
                            evtx.get_record(args.record).root(),
                            suppress_values=args.suppress_values)
        print evtx_record_xml_view(evtx.get_record(args.record))


if __name__ == "__main__":
    main()
