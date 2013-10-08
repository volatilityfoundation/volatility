# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

try:
    import distorm3
    has_distorm = True
except ImportError:
    has_distorm = False

class linux_check_syscall(linux_common.AbstractLinuxCommand):
    """ Checks if the system call table has been altered """

    def _get_table_size(self, table_addr, table_name):
        """
        Returns the size of the table based on the next symbol
        """

        # take this from the size of an address in the profile 
        divisor = self.profile.get_obj_size("address")

        next_sym_addr = self.profile.get_next_symbol_address(table_name)

        return (next_sym_addr - table_addr) / divisor

    def _get_table_size_meta(self):
        """
        returns the number of symbols that start with __syscall_meta
        this is a fast way to determine the number of system calls
        """

        return len([n for n in self.profile.get_all_symbol_names() if n.startswith("__syscall_meta__")])

    def _get_table_info_other(self, table_addr, table_name):
        table_size_meta = self._get_table_size_meta()
        table_size_syms = self._get_table_size(table_addr, table_name)

        sizes = [size for size in [table_size_meta, table_size_syms] if size > 0]

        table_size = min(sizes)

        return table_size

    def _get_table_info_distorm(self):
        """
        Find the size of the system call table by disassembling functions
        that immediately reference it in their first isntruction
        This is in the form 'cmp reg,NR_syscalls'
        """
        table_size = 0

        if not has_distorm:
            return table_size

        memory_model = self.addr_space.profile.metadata.get('memory_model', '32bit')

        if memory_model == '32bit':
            mode = distorm3.Decode32Bits
            func = "sysenter_do_call"
        else:
            mode = distorm3.Decode64Bits
            func = "system_call_fastpath"

        func_addr = self.addr_space.profile.get_symbol(func)

        if func_addr:

            data = self.addr_space.read(func_addr, 6)

            for op in distorm3.Decompose(func_addr, data, mode):

                if not op.valid:
                    continue

                if op.mnemonic == 'CMP':
                    table_size = (op.operands[1].value) & 0xffffffff
                    break

        return table_size

    def _get_table_info(self, table_name):
        table_addr = self.addr_space.profile.get_symbol(table_name)

        table_size = self._get_table_info_distorm()

        if table_size == 0:

            table_size = self._get_table_info_other(table_addr, table_name)

            if table_size == 0:
                debug.error("Unable to get system call table size")

        return [table_addr, table_size]

    def calculate(self):
        """ 
        This works by walking the system call table 
        and verifies that each is a symbol in the kernel
        """
        linux_common.set_plugin_members(self)

        if not has_distorm:
            debug.warning("distorm not installed. The best method to calculate the system call table size will not be used.")

        table_name = self.addr_space.profile.metadata.get('memory_model', '32bit')
        sym_addrs = self.profile.get_all_addresses()
        sys_call_info = self._get_table_info("sys_call_table")
        addrs = [(table_name, sys_call_info)]

        # 64 bit systems with 32 bit emulation
        ia32 = self.addr_space.profile.get_symbol("ia32_sys_call_table")
        if ia32:
            ia32_info = self._get_table_info("ia32_sys_call_table")
            addrs.append(("32bit", ia32_info))

        for (table_name, (tableaddr, tblsz)) in addrs:

            table = obj.Object(theType = 'Array', offset = tableaddr, vm = self.addr_space, targetType = 'unsigned long', count = tblsz)

            for (i, call_addr) in enumerate(table):

                if not call_addr:
                    continue

                call_addr = int(call_addr)

                if not call_addr in sym_addrs:
                    hooked = 1
                    sym_name = "HOOKED"
                else:
                    hooked = 0 
                    sym_name = self.profile.get_symbol_by_address("kernel", call_addr)
                
                yield(tableaddr, table_name, i, call_addr, sym_name, hooked)
    
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Table Name", "6"), ("Index", "[addr]"), ("Address", "[addrpad]"), ("Symbol", "<30")])
        for (tableaddr, table_name, i, call_addr, sym_name, hooked) in data:
            self.table_row(outfd, table_name, i, call_addr, sym_name)



