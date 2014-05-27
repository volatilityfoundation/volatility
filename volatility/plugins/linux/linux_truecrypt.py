# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.malware.malfind as malfind

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

class PassphraseScanner(malfind.BaseYaraScanner):
    """A scanner over all memory regions of a process."""

    def __init__(self, task = None, **kwargs):
        """Scan the process address space through the VMAs.

        Args:
          task: The task_struct object for this task.
        """
        self.task = task
        malfind.BaseYaraScanner.__init__(self, 
                    address_space = task.get_process_address_space(), 
                    **kwargs)

    def scan(self, offset = 0, maxlen = None):

        profile = self.address_space.profile
        offset = profile.get_obj_offset("PASSPHRASE", "MaxLength")

        for vma in self.task.get_proc_maps():

            # only scanning the process heap
            if not (vma.vm_start <= self.task.mm.start_brk 
                    and vma.vm_end >= self.task.mm.brk):
                continue

            for hit, address in malfind.BaseYaraScanner.scan(self, 
                       vma.vm_start, 
                       vma.vm_end - vma.vm_start):

                # possible passphrase structure 
                passt = obj.Object("PASSPHRASE", 
                                   offset = address - offset, 
                                   vm = self.address_space)

                # the sanity checks
                if (passt and vma.vm_start <= passt.Text and 
                          vma.vm_end >= passt.Text and 
                          passt.Length > 0 and 
                          passt.Length < passt.MaxLength):

                    password = passt.Text.dereference()
                    if len(password) != passt.Length:
                        continue

                    yield address, password

class LinuxTruecryptModification(obj.ProfileModification):
    """A modification for Linux Truecrypt passphrases"""

    conditions = {'os': lambda x: x == 'linux'}

    def modification(self, profile):

        x86_vtypes =  {
                'PASSPHRASE': [ None, {
                'Text': [ 0, ['pointer', ['String', dict(length = 255)]]], 
                'MaxLength': [ 0x4, ['int']], 
                'Length': [ 0x8, ['int']],
                }]}
        x64_vtypes = {
                'PASSPHRASE': [ None, {
                'Text': [ 0, ['pointer', ['String', dict(length = 255)]]], 
                'MaxLength': [ 0x8, ['int']], 
                'Length': [ 0xC, ['int']],
                }]}

        bits = profile.metadata.get("memory_model", "32bit")

        if bits == "32bit":
            vtypes = x86_vtypes
        else:
            vtypes = x64_vtypes 

        profile.vtypes.update(vtypes)

class linux_truecrypt_passphrase(linux_pslist.linux_pslist):
    """ Recovers cached Truecrypt passphrases """

    def calculate(self):

        ## we need this module imported
        if not has_yara:
            debug.error("Please install Yara from https://plusvic.github.io/yara/")

        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            if str(task.comm) != "truecrypt":
                continue

            space = task.get_process_address_space()
            if not space:
                continue
    
            rules = yara.compile(sources = {
               'n' : 'rule r1 {strings: $a = {40 00 00 00 ?? 00 00 00} condition: $a}'
               })

            scanner = PassphraseScanner(task = task, rules = rules)
            for address, password in scanner.scan():
                yield task, address, password

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Process", "16"), 
                                  ("Pid", "8"),
                                  ("Address", "[addrpad]"), 
                                  ("Password", "")])

        for (task, address, password) in data:
            self.table_row(outfd, task.comm, task.pid, address, password)