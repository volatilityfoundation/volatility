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
import logging

from recovery_utils import TemplateDatabase


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Merge existing template files, deduping identical templates.")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debugging output")
    parser.add_argument("templates_outfile", type=str,
                        help="Path to the output template file")
    parser.add_argument("templates_files", type=str, nargs="+",
                        help="Path to the template files")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s %(name)s %(message)s")

    templates = TemplateDatabase()

    for file_ in args.templates_files:
        new_templates = TemplateDatabase()
        with open(file_, "rb") as f:
            new_templates.deserialize(f.read(), warn_on_conflict=False)
        templates.extend(new_templates)

    with open(args.templates_outfile, "wb") as f:
        f.write(templates.serialize())


if __name__ == "__main__":
    main()
