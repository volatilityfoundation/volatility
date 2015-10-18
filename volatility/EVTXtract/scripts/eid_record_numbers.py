from lxml.etree import XMLSyntaxError
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

from filter_records import get_child
from filter_records import to_lxml


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Print the record numbers of EVTX log entries "
                    "that match the given EID.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("eid", type=int,
                        help="The EID of records to extract")
    args = parser.parse_args()

    with Evtx(args.evtx) as evtx:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                node = to_lxml(xml)
            except XMLSyntaxError:
                continue
            if args.eid != int(get_child(get_child(node, "System"), "EventID").text):
                continue
            print record.record_num()


if __name__ == "__main__":
    main()
