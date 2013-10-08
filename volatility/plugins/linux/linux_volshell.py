# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
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

import volatility.plugins.linux.pslist as pslist
import volatility.plugins.linux.lsmod as lsmod
import volatility.plugins.volshell as volshell
import volatility.obj as obj

class linux_volshell(volshell.volshell):
    """Shell in the memory image"""

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'linux'

    def modules(self):
        mods = lsmod.linux_lsmod(self._config).calculate()

        for (module, _, __) in mods:
            print "{0:24} {1:d}".format(module.name, module.init_size + module.core_size)

    def getpidlist(self):
        return pslist.linux_pslist(self._config).calculate()

    def ps(self, procs = None):
        print "{0:16} {1:6} {2:8}".format("Name", "PID", "Offset")
        for proc in procs or self.getpidlist():
            print "{0:16} {1:<6} {2:#08x}".format(proc.comm, proc.pid, proc.obj_offset)

    def context_display(self):
        dtb = self.addrspace.vtop(self.proc.mm.pgd) or self.proc.mm.pgd
        print "Current context: process {0}, pid={1} DTB={2:#x}".format(self.proc.comm,
                                                                        self.proc.pid, dtb)

    def set_context(self, offset = None, pid = None, name = None):
        if pid is not None:
            offsets = []
            for p in self.getpidlist():
                if p.pid.v() == pid:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching pid {0}".format(pid)
                return
            elif len(offsets) > 1:
                print "Multiple processes match {0}, please specify by offset".format(pid)
                print "Matching processes:"
                self.ps(offsets)
                return
            else:
                offset = offsets[0].v()
        elif name is not None:
            offsets = []
            for p in self.getpidlist():
                if p.comm.find(name) >= 0:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching name {0}".format(name)
                return
            elif len(offsets) > 1:
                print "Multiple processes match name {0}, please specify by PID or offset".format(name)
                print "Matching processes:"
                self.ps(offsets)
                return
            else:
                offset = offsets[0].v()
        elif offset is None:
            print "Must provide one of: offset, name, or pid as a argument."
            return

        self.proc = obj.Object("task_struct", offset = offset, vm = self.addrspace)

        self.context_display()
