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
@author:       Jared Smith
@license:      GNU General Public License 2.0
@contact:      jaredsmith359@gmail.com
@organization: Volatility Foundation
"""


import volatility
import volatility.conf as conf
import volatility.plugins.common as common
import volatility.utils as utils
import os, subprocess, ntpath
import string


config = conf.config


class EvtxLogs(common.AbstractWindowsCommand):

    """Extract Windows Event Logs (Vista/7/8/10 only)"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump log files')

    @staticmethod
    def is_valid_profile(profile):
        """This plugin is valid on Vista and later"""
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 6)

    def calculate(self):
        evtxpath = os.path.dirname(volatility.__file__)
        image_path = (config.LOCATION).replace('file://', '')
        image_path = image_path.replace('%28', '(')
        image_path = image_path.replace('%29', ')')

        args_1 = [
            'python',
            '{}/EVTXtract/find_evtx_chunks.py'.format(evtxpath),
            '{}'.format(image_path)
        ]
        result = subprocess.check_output(args_1)
        args_2 = [
            'python',
            '{}/EVTXtract/extract_valid_evtx_records_and_templates.py'.format(evtxpath),
            '{}'.format(image_path)
        ]
        result = subprocess.check_output(args_2)
        args_3 = [
            'python',
            '{}/EVTXtract/find_evtx_records.py'.format(evtxpath),
            '{}'.format(image_path)
        ]
        result = subprocess.check_output(args_3)
        args_4 = [
            'python',
            '{}/EVTXtract/show_valid_records.py'.format(evtxpath),
            '{}'.format(image_path)
        ]
        records = subprocess.check_output(args_4)

        return records

    def render_text(self, outfd, data):
        name = 'evtx-output.txt'
        fh = open(os.path.join(self._config.DUMP_DIR, name), 'wb')
        fh.write(data)
        fh.close()
        outfd.write('Parsed data sent to {0}\n'.format(name))
