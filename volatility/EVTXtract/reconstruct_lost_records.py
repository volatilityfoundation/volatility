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
import logging
from Progress import NullProgress
from State import State
from TemplateDatabase import TemplateEIDConflictError, TemplateNotFoundError, TemplateDatabase

from recovery_utils import do_common_argparse_config

logger = logging.getLogger("reconstruct_lost_records")


def reconstruct_lost_records(state, templates, progress_class=NullProgress):
    """
    @type state: State
    @type templates: TemplateDatabase
    @rtype: (int, int)
    @return: The number of reconstructed records, and the number of unreconstructed records.
    """
    num_reconstructed = 0
    num_unreconstructed = 0
    if len(state.get_lost_records()) == 0:
        return num_reconstructed, num_unreconstructed
    progress = progress_class(len(state.get_lost_records()))
    for i, lost_record in enumerate(state.get_lost_records()):
        progress.set_current(i)
        eid = lost_record["substitutions"][3][1]
        try:
            logger.debug("Fetching template for record %d with EID: %d num_subs: %d" %
                         (lost_record["record_num"], eid, len(lost_record["substitutions"])))
            template = templates.get_template(eid, lost_record["substitutions"])
        except TemplateEIDConflictError as e:
            state.add_unreconstructed_record(lost_record["offset"], lost_record["substitutions"], str(e))
            num_unreconstructed += 1
            logger.debug("Unable to reconstruct record with EID %d: %s", eid, str(e))
            continue
        except TemplateNotFoundError as e:
            state.add_unreconstructed_record(lost_record["offset"], lost_record["substitutions"], str(e))
            num_unreconstructed += 1
            logger.debug("Unable to reconstruct record with EID %d: %s", eid, str(e))
            continue
        subs = map(lambda s: (s[0], str(s[1])), lost_record["substitutions"])
        state.add_reconstructed_record(lost_record["offset"], eid, template.insert_substitutions(subs))
        num_reconstructed += 1
        logger.debug("Reconstructed record with EID %d", eid)
    progress.set_complete()
    return num_reconstructed, num_unreconstructed


def main():
    args = do_common_argparse_config("Reconstruct lost EVTX records using recovered templates.")
    with State(args.project_json) as state:
        with TemplateDatabase(args.templates_json) as templates:
            num_reconstructed, num_unreconstructed = reconstruct_lost_records(state, templates, progress_class=args.progress_class)
    print("# Reconstructed %d records." % num_reconstructed)
    print("# Failed to reconstruct %d records." % num_unreconstructed)


if __name__ == "__main__":
    main()
