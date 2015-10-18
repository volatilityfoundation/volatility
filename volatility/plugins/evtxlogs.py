# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie@memoryanalysis.net>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie@memoryanalysis.net
@organization: Volatility Foundation
"""

import volatility.utils as utils
import volatility.plugins.getsids as getsids
import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.getservicesids as getservicesids
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.debug as debug
import os, datetime, ntpath
from volatility.renderers import TreeGrid


class EvtxLogs(common.AbstractWindowsCommand):
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('SAVE-EVTX', short_option = 'S', default = False,
                          action = 'store_true', help = 'Save the raw .evtx files also')

        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump executable files')

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) > 5)

    def calculate(self):
        """The calculate function should carry out the main operation against any memory images being analyzed.
        This function takes no arguments and returns a single "data" variable, which can be of any form as long
        as it is then successfully processed by the plugin's render_<type> functions."""
        pass

    def parse_evtx_info(self):
        pass

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for name, buf in data:
            ## We can use the ntpath module instead of manually replacing the slashes
            ofname = ntpath.basename(name)

            ## Dump the raw event log so it can be parsed with other tools
            if self._config.SAVE_EVTX:
                fh = open(os.path.join(self._config.DUMP_DIR, ofname), 'wb')
                fh.write(buf)
                fh.close()
                outfd.write('Saved raw .evtx file to {0}\n'.format(ofname))

            ## Now dump the parsed, pipe-delimited event records to a file
            ofname = ofname.replace(".evt", ".txt")
            fh = open(os.path.join(self._config.DUMP_DIR, ofname), 'wb')
            for fields in self.parse_evt_info(name, buf):
                fh.write('|'.join(fields) + "\n")
            fh.close()
            outfd.write('Parsed data sent to {0}\n'.format(ofname))
