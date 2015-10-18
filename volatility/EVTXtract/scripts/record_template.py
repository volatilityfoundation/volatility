from Evtx.Evtx import Evtx
from Evtx.Views import evtx_template_readable_view


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Print the structure of an EVTX record's template.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("record", type=int,
                        help="Record number")
    args = parser.parse_args()

    with Evtx(args.evtx) as evtx:
        r = evtx.get_record(args.record)
        print evtx_template_readable_view(r.root())


if __name__ == "__main__":
    main()
