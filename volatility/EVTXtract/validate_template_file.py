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
#
#   Version v0.1
import sys

from recovery_utils import TemplateDatabase
from recovery_utils import TemplateEIDConflictError


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Verify a template file's syntax and contents.")
    parser.add_argument("templates", type=str,
                        help="Path to the file containing recovered templates")
    args = parser.parse_args()

    with open(args.templates, "rb") as f:
        templates_txt = f.read()

    # we break rules below be reaching into `templates`. Sorry :-(
    templates = TemplateDatabase()
    try:
        templates.deserialize(templates_txt, warn_on_conflict=True)

        print "Template Distribution:"
        for eid in sorted(templates._eid_map.keys()):
            print "  EID: %6d  --> %2d templates" % \
                (eid, len(templates._eid_map[eid]))

        print ""
        print "  Summary   "
        print "-------------"
        print "No Conflicts!"
        sys.exit(0)
    except TemplateEIDConflictError:
        templates.deserialize(templates_txt, warn_on_conflict=False)

        print "Template Distribution:"
        for eid in sorted(templates._eid_map.keys()):
            ids = []
            tt = []
            for id_ in templates._eid_map[eid]:
                tt.extend(templates._templates[id_])
                ids.append(id_)

            if len(ids) != len(tt):
                print "  EID: %6d  --> %2d templates (%d conflicts)" % \
                    (eid, len(tt), len(tt) - len(ids))
            else:
                print "  EID: %6d  --> %2d templates" % \
                    (eid, len(templates._eid_map[eid]))

        print ""
        print "        Summary        "
        print "-----------------------"

        print "There are %d Conflicts!" % \
            (sum(map(len, templates._templates.values())) - len(templates._templates.keys()))
        sys.exit(-1)


if __name__ == "__main__":
    main()
