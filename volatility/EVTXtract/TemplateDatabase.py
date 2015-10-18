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
import json
import logging
import os
import re
from recovery_utils import exists

CURRENT_VERSION = 1
GENERATOR = "recover-evtx"
logger = logging.getLogger("template_database")


def touch(path):
    open(path, 'a').close()


class IncompatibleVersionException(Exception):
    def __init__(self, msg):
        super(IncompatibleVersionException, self).__init__()
        self._msg = msg

    def __str__(self):
        return "IncompatibleVersionException(%s)" % self._msg


class TemplateEIDConflictError(Exception):
    def __init__(self, value):
        super(TemplateEIDConflictError, self).__init__(value)


class TemplateNotFoundError(Exception):
    def __init__(self, value):
        super(TemplateNotFoundError, self).__init__(value)


class Template(object):
    substitition_re = re.compile("\[(Conditional|Normal) Substitution\(index=(\d+), type=(\d+)\)\]")

    def __init__(self, eid, xml):
        self._eid = eid
        self._xml = xml

        self._cached_placeholders = None
        self._cached_id = None

    def get_xml(self):
        return self._xml

    def get_eid(self):
        return self._eid

    def get_id(self):
        """
        @rtype: str
        @return: A string that can be parsed into constraints describing what
          types of subsitutions this template can accept.
          Short example: 1100-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]
        """
        if self._cached_id is not None:
            return self._cached_id
        ret = ["%s" % self._eid]
        for index, type_, mode in self._get_placeholders():
            if mode:
                mode_str = "c"
            else:
                mode_str = "n"
            ret.append("[%s|%s|%s]" % (index, type_, mode_str))
        self._cached_id = "-".join(ret)
        return self._cached_id

    def _get_placeholders(self):
        """
        Get descriptors for each of the substitutions required by this
          template.

        Tuple schema: (index, type, is_conditional)

        @rtype: list of (int, int, boolean)
        """
        if self._cached_placeholders is not None:
            return self._cached_placeholders
        ret = []
        for mode, index, type_ in Template.substitition_re.findall(self._xml):
            ret.append((int(index), int(type_), mode == "Conditional"))
        self._cached_placeholders = sorted(ret, key=lambda p: p[0])
        return self._cached_placeholders

    def match_substitutions(self, substitutions):
        """
        Checks to see if the provided set of substitutions match the
          placeholder values required by this template.

        Note, this is only a best guess.  The number of substitutions
          *may* be greater than the number of available slots. So we
          must only check the slot and substitution types.



        @type substitutions: list of (int, str)
        @param substitutions: Tuple schema (type, value)
        @rtype: boolean
        """
        logger = logging.getLogger("match_substitutions")
        placeholders = self._get_placeholders()
        logger.debug("Substitutions: %s", str(substitutions))
        logger.debug("Constraints: %s", str(placeholders))
        if len(placeholders) > len(substitutions):
            logger.debug("Failing on lens: %d vs %d",
                         len(placeholders), len(substitutions))
            return False
        if max(placeholders, key=lambda k: k[0])[0] > len(substitutions):
            logger.debug("Failing on max index: %d vs %d",
                         max(placeholders, key=lambda k: k[0])[0],
                         len(substitutions))
            return False

        # it seems that some templates request different values than what are subsequently put in them
        #   specifically, a Hex64 might be put into a SizeType field (EID 4624)
        # this maps from the type described in a template, to possible additional types that a
        #   record can provide for a particular substitution
        overrides = {
            16: set([21])
        }

        for index, type_, is_conditional in placeholders:
            sub_type, sub_value = substitutions[index]
            if is_conditional and sub_type == 0:
                continue
            if sub_type != type_:
                if type_ not in overrides or sub_type not in overrides[type_]:
                    logger.debug("Failing on type comparison, index %d: %d vs %d (mode: %s)",
                                 index, sub_type, type_, is_conditional)
                    return False
                else:
                    logger.debug("Overriding template type %d with substitution type %d", type_, sub_type)
                    continue
        return True

    escape_re = re.compile(r"\\\\(\d)")

    @staticmethod
    def _escape(value):
        """
        Escape the static value to be used in a regular expression
          subsititution. This processes any backreferences and
          makes them plain, escaped sequences.

        @type value: str
        @rtype: str
        """
        return Template.escape_re.sub(r"\\\\\\\\\1", re.escape(value))

    def insert_substitutions(self, substitutions):
        """
        Return a copy of the template with the given substitutions inserted.

        @type substitutions: list of (int, str)
        @param substitutions: an ordered list of (type:int, value:str)
        @rtype: str
        """
        ret = self._xml
        for index, pair in enumerate(substitutions):
            type_, value = pair
            from_pattern = "\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % index
            ret = re.sub(from_pattern, Template._escape(value), ret)
        return ret


class TemplateDatabase(object):
    """
    Class that loads and saves Templates to a persistent file.
    """
    def __init__(self, filename):
        self._filename = filename
        # this is a JSON-compatible structure that is truth
        #   see README for schema
        self._state = {}

        # this is a cache of instantiated Templates. it is not persisted to disk
        #   but loaded instances should always match whats in self._state
        #   not all instances may be loaded at any given time, however
        # schema is similar to state.templates:
        #   (str)eid -> list of Template instances
        self._cached_templates = {}

    def __enter__(self):
        if not os.path.exists(self._filename):
            logger.debug("Creating template file: %s", self._filename)
            touch(self._filename)
        else:
            logger.debug("Using existing template file: %s", self._filename)

        with open(self._filename, "rb") as f:
            self._state = json.loads(f.read() or "{}")

        if self._get_version() != CURRENT_VERSION and self._get_version() != "":
            raise IncompatibleVersionException("Version %d expected, got %d" %
                                               (CURRENT_VERSION, self._get_version()))

        self._set_version(CURRENT_VERSION)
        if self._get_generator() == "":
            self._set_generator(GENERATOR)
        return self

    def __exit__(self, type_, value, traceback):
        if not os.path.exists(self._filename):
            logger.debug("Creating template file: %s", self._filename)
            touch(self._filename)
        else:
            logger.debug("Using existing template file: %s", self._filename)

        with open(self._filename, "wb") as f:
            f.write(json.dumps(self._state, sort_keys=True,
                               indent=4, separators=(',', ': ')))
        if value:
            logging.warn("Flushing the existing template file due to exception.")
            return False

    def _set_version(self, version):
        self._state["version"] = version

    def _get_version(self):
        return self._state.get("version", "")

    def _set_generator(self, generator):
        self._state["generator"] = generator

    def _get_generator(self):
        return self._state.get("generator", "")

    def add_template(self, template):
        """
        @type template: Template
        """
        eid = template.get_eid()
        xml = template.get_xml()
        id_ = template.get_id()

        all_templates = self._state.get("templates", {})
        correct_eid_templates = all_templates.get(str(eid), [])
        if not exists(lambda t: t["id"] == id_ and
                                t["xml"] == xml, correct_eid_templates):
            correct_eid_templates.append({
                "eid": eid,
                "id": id_,
                "xml": xml
            })
            all_templates[eid] = correct_eid_templates
        self._state["templates"] = all_templates

        correct_eid_template_instances = self._cached_templates.get(str(eid), [])
        if not exists(lambda t: t.get_id() == id_ and
                                t.get_xml() == xml, correct_eid_template_instances):
            correct_eid_template_instances.append(template)
            self._cached_templates[str(eid)] = correct_eid_template_instances

    def get_template(self, eid, substitutions):
        """
        Given an EID and a set of substitutions, pick a template that
          matches the constraints.

        @type eid: int
        @type substitutions: list of (int, str)
        @rtype: Template
        @raises TemplateEIDConflictError
        @raises TemplateNotFoundError
        """
        if str(eid) not in self._cached_templates:
            all_templates = self._state.get("templates", {})
            if str(eid) not in all_templates:
                raise TemplateNotFoundError("No loaded templates with EID: %s" % eid)

            # need to load cache
            potential_templates = all_templates.get(str(eid), [])
            potential_templates = map(lambda t: Template(eid, t["xml"]), potential_templates)
            self._cached_templates[str(eid)] = potential_templates
        else:
            # already in cache
            potential_templates = self._cached_templates[str(eid)]

        matching_templates = []
        logger.debug("considering %d possible templates based on EID", len(potential_templates))
        for template in potential_templates:
            if template.match_substitutions(substitutions):
                matching_templates.append(template)

        if len(matching_templates) > 1:
            matches = map(lambda t: t.get_id(), matching_templates)
            raise TemplateEIDConflictError("%d templates matched query for "
                                           "EID %d and substitutions: %s" %
                                           (len(matching_templates), eid, matches))

        if len(matching_templates) == 0:
            # example: "1100-[0|4| ]-[1|4| ]-[2|6| ]-[3|6| ]"
            sig = str(eid) + "-" + "-".join(["[%d|%d| ]" % (i, j) for i, j in \
                                                 enumerate(map(lambda p: p[0], substitutions))])
            raise TemplateNotFoundError("No loaded templates with given "
                                        "substitution signature: %s" % sig)

        return matching_templates[0]

    def get_number_of_templates(self):
        """
        Get the number of templates tracked in this database.

        @rtype: int
        @return: The number of templates tracked in this database.
        """
        return sum(map(len, self._state.get("templates", {}).values()))
