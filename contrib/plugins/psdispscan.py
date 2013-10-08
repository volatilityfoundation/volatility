# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
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
This module implements the slow thorough process scanning

@author:       Michael Cohen
@license:      GNU General Public License 2.0 or later
@contact:      scudette@users.sourceforge.net
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import volatility.commands as commands
import volatility.cache as cache
import volatility.utils as utils
import volatility.obj as obj
import volatility.scan as scan

class DispatchHeaderCheck(scan.ScannerCheck):
    """ A very fast check for an _EPROCESS.Pcb.Header.

    This check assumes that the type and size of
    _EPROCESS.Pcb.Header are unsigned chars, but allows their
    offsets to be determined from vtypes (so they could change
    between OS versions).
    """
    order = 10

    def __init__(self, address_space, **_kwargs):
        ## Because this checks needs to be super fast we first
        ## instantiate the _EPROCESS and work out the offsets of the
        ## type and size members. Then in the check we just read those
        ## offsets directly.
        eprocess = obj.Object("_EPROCESS", vm = address_space, offset = 0)
        self.type = eprocess.Pcb.Header.Type
        self.size = eprocess.Pcb.Header.Size
        self.buffer_size = max(self.size.obj_offset, self.type.obj_offset) + 2
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        data = self.address_space.read(offset + self.type.obj_offset, self.buffer_size)
        return data[self.type.obj_offset] == "\x03" and data[self.size.obj_offset] == "\x1b"

    def skip(self, data, offset):
        try:
            nextval = data.index("\x03", offset + 1)
            return nextval - self.type.obj_offset - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset

class CheckThreadList(scan.ScannerCheck):
    """ Checks that _EPROCESS thread list points to the kernel Address Space """
    def check(self, offset):
        eprocess = obj.Object("_EPROCESS", vm = self.address_space,
                             offset = offset)
        kernel = 0x80000000

        list_head = eprocess.ThreadListHead

        if list_head.Flink > kernel and list_head.Blink > kernel:
            return True

class CheckDTBAligned(scan.ScannerCheck):
    """ Checks that _EPROCESS.Pcb.DirectoryTableBase is aligned to 0x20 """
    def check(self, offset):
        eprocess = obj.Object("_EPROCESS", vm = self.address_space,
                             offset = offset)

        return eprocess.Pcb.DirectoryTableBase % 0x20 == 0

class CheckSynchronization(scan.ScannerCheck):
    """ Checks that _EPROCESS.WorkingSetLock and _EPROCESS.AddressCreationLock look valid """
    def check(self, offset):
        eprocess = obj.Object("_EPROCESS", vm = self.address_space,
                             offset = offset)

        event = eprocess.WorkingSetLock.Event.Header
        if event.Type != 0x1 or event.Size != 0x4:
            return False

        event = eprocess.AddressCreationLock.Event.Header
        if event.Size == 0x4 and event.Type == 0x1:
            return True

class PSDispScanner(scan.BaseScanner):
    """ This scanner carves things that look like _EPROCESS structures.

    Since the _EPROCESS does not need to be linked to the process
    list, this scanner is useful to recover terminated or cloaked
    processes.
    """
    checks = [ ("DispatchHeaderCheck", {}),
               ("CheckDTBAligned", {}),
               ("CheckThreadList", {}),
               ("CheckSynchronization", {})
               ]

class PSDispScan(commands.Command, cache.Testable):
    """ Scan Physical memory for _EPROCESS objects based on their Dispatch Headers"""

    # Declare meta information associated with this plugin

    meta_info = dict(
        author = 'Brendan Dolan-Gavitt',
        copyright = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        contact = 'bdolangavitt@wesleyan.edu',
        license = 'GNU General Public License 2.0 or later',
        url = 'http://moyix.blogspot.com/',
        os = 'WIN_32_XP_SP2',
        version = '1.0',
        )

    @cache.CacheDecorator("tests/psscan")
    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        for offset in PSDispScanner().scan(address_space):
            yield obj.Object('_EPROCESS', vm = address_space, offset = offset)

    def render_dot(self, outfd, data):
        objects = set()
        links = set()

        for eprocess in data:
            label = "{0} | {1} |".format(eprocess.UniqueProcessId,
                                         eprocess.ImageFileName)
            if eprocess.ExitTime:
                label += "exited\\n{0}".format(eprocess.ExitTime)
                options = ' style = "filled" fillcolor = "lightgray" '
            else:
                label += "running"
                options = ''

            objects.add('pid{0} [label="{1}" shape="record" {2}];\n'.format(eprocess.UniqueProcessId,
                                                                            label, options))
            links.add("pid{0} -> pid{1} [];\n".format(eprocess.InheritedFromUniqueProcessId,
                                                      eprocess.UniqueProcessId))

        ## Now write the dot file
        outfd.write("digraph processtree { \ngraph [rankdir = \"TB\"];\n")
        for link in links:
            outfd.write(link)

        for item in objects:
            outfd.write(item)
        outfd.write("}")

    def render_text(self, outfd, data):
        ## Just grab the AS and scan it using our scanner
        outfd.write(" Offset     Name             PID    PPID   PDB        Time created             Time exited             \n" +
                    "---------- ---------------- ------ ------ ---------- ------------------------ ------------------------ \n")

        for eprocess in data:
            outfd.write("{0:#010x} {1:16} {2:6} {3:6} {4:#010x} {5:24} {6:24}\n".format(
                eprocess.obj_offset,
                eprocess.ImageFileName,
                eprocess.UniqueProcessId,
                eprocess.InheritedFromUniqueProcessId,
                eprocess.Pcb.DirectoryTableBase,
                eprocess.CreateTime or '',
                eprocess.ExitTime or ''))
