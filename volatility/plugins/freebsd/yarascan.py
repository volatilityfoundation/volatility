# Volatility
# Copyright (C) 2019 Volatility Foundation
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

import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.freebsd.common as freebsd_common
import volatility.plugins.freebsd.pslist as freebsd_pslist
import volatility.plugins.malware.malfind as malfind
import re

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

class MapYaraScanner(malfind.BaseYaraScanner):
    """A scanner over all memory regions of a process."""

    def __init__(self, proc = None, **kwargs):
        """Scan the process address space through the address map entries.

        Args:
          proc: The proc object for this process.
        """
        self.proc = proc
        malfind.BaseYaraScanner.__init__(self, address_space = proc.get_process_address_space(), **kwargs)

    def scan(self, offset = 0, maxlen = None):
        for entry in self.proc.get_proc_maps():
            for match in malfind.BaseYaraScanner.scan(self, entry.start, entry.end - entry.start):
                yield match

class freebsd_yarascan(malfind.YaraScan):
    """Scan memory for yara signatures"""

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'freebsd'

    def filter_tasks(self):
        procs = freebsd_pslist.freebsd_pslist(self._config).calculate()

        if self._config.PID is not None:
            try:
                pidlist = [int(p) for p in self._config.PID.split(',')]
            except ValueError:
                debug.error('Invalid PID {0}'.format(self._config.PID))

            pids = [t for t in procs if t.p_pid in pidlist]
            if len(pids) == 0:
                debug.error('Cannot find PID {0}.'.format(self._config.PID))
            return pids

        if self._config.NAME is not None:
            try:
                name_re = re.compile(self._config.NAME, re.I)
            except re.error:
                debug.error('Invalid name {0}'.format(self._config.NAME))

            names = [t for t in procs if name_re.search(str(t.p_comm))]
            if len(names) == 0:
                debug.error('Cannot find name {0}.'.format(self._config.NAME))
            return names

        return procs

    def calculate(self):

        ## we need this module imported
        if not has_yara:
            debug.error('Please install Yara from https://plusvic.github.io/yara/')

        ## leveraged from the windows yarascan plugin
        rules = self._compile_rules()

        ## set the freebsd plugin address spaces
        freebsd_common.set_plugin_members(self)

        if self._config.KERNEL or self._config.ALL:
            scanner = malfind.DiscontigYaraScanner(rules = rules,
                                                   address_space = self.addr_space)

            for hit, address in scanner.scan():
                yield (None, address - self._config.REVERSE, hit,
                       scanner.address_space.zread(address - self._config.REVERSE, self._config.SIZE))
        if not self._config.KERNEL or self._config.ALL:
            # Scan each process memory block
            procs = self.filter_tasks()
            for proc in procs:
                scanner = MapYaraScanner(proc = proc, rules = rules)
                for hit, address in scanner.scan():
                    yield (proc, address - self._config.REVERSE, hit,
                           scanner.address_space.zread(address - self._config.REVERSE, self._config.SIZE))

    def render_text(self, outfd, data):
        for proc, address, hit, buf in data:
            if proc:
                outfd.write('Proc: {0} pid {1} rule {2} addr {3:#x}\n'.format(
                    proc.p_comm, proc.p_pid, hit.rule, address))
            else:
                outfd.write('[kernel] rule {0} addr {1:#x}\n'.format(hit.rule, address))

            outfd.write(''.join(['{0:#018x}  {1:<48}  {2}\n'.format(
                address + o, h, ''.join(c)) for o, h, c in utils.Hexdump(buf)]))
