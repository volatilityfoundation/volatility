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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

idt_vtype_64 = {
    'idt_desc': [ 16 , {
    'offset_low'    : [0,  ['unsigned short']],
    'segment'       : [2,  ['unsigned short']],
    'ist'           : [4,  ['unsigned short']],
    'offset_middle' : [6,  ['unsigned short']],
    'offset_high'   : [8,  ['unsigned int']],
    'unused'        : [12, ['unsigned int']],  
    }],
}

class LinuxIDTTypes(obj.ProfileModification):
    conditions = {"os" : lambda x : x in ["linux"]}

    def modification(self, profile):       
        if profile.metadata.get('memory_model', '64bit') == "64bit":
            profile.vtypes.update(idt_vtype_64)


class linux_check_idt(linux_common.AbstractLinuxCommand):
    """ Checks if the IDT has been altered """

    def calculate(self):
        """ 
        This works by walking the IDT table for the entries that Linux uses
        and verifies that each is a symbol in the kernel
        """
        linux_common.set_plugin_members(self)

        if self.profile.metadata['arch'] not in ["x64", "x86"]:
            debug.error("This plugin is only supported on Intel-based memory captures") 

        tblsz = 256

        sym_addrs = self.profile.get_all_addresses()

        # hw handlers + system call
        check_idxs = list(range(0, 20)) + [128]

        if self.profile.metadata.get('memory_model', '32bit') == "32bit":
            idt_type = "desc_struct"
        else:
            if self.profile.has_type("gate_struct64"):
                idt_type = "gate_struct64"
            else:
                idt_type = "idt_desc"

        # this is written as a list b/c there are supposdly kernels with per-CPU IDTs
        # but I haven't found one yet...
        addrs = [self.addr_space.profile.get_symbol("idt_table")]

        for tableaddr in addrs:
            table = obj.Object(theType = 'Array', offset = tableaddr, vm = self.addr_space, targetType = idt_type, count = tblsz)

            for i in check_idxs:
                ent = table[i]

                if not ent:
                    continue

                if hasattr(ent, "Address"):
                    idt_addr = ent.Address
                else:
                    low    = ent.offset_low
                    middle = ent.offset_middle
                    high   = ent.offset_high

                    idt_addr = (high << 32) | (middle << 16) | low

                if idt_addr != 0:
                    if not idt_addr in sym_addrs:
                        hooked = 1
                        sym_name = "HOOKED"
                    else:
                        hooked = 0
                        sym_name = self.profile.get_symbol_by_address("kernel", idt_addr)

                    yield(i, ent, idt_addr, sym_name, hooked)

    def unified_output(self, data):
        return TreeGrid([("Index", Address),
                       ("Address", Address),
                       ("Symbol", str)],
                        self.generator(data))

    def generator(self, data):
        for (i, _, idt_addr, sym_name, hooked) in data:
            yield (0, [Address(i), Address(idt_addr), str(sym_name)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Index", "[addr]"), ("Address", "[addrpad]"), ("Symbol", "<30")])

        for (i, _, idt_addr, sym_name, hooked) in data:
            self.table_row(outfd, i, idt_addr, sym_name)

