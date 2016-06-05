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

import os

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod as linux_lsmod
import volatility.plugins.linux.hidden_modules as linux_hidden_modules
import volatility.plugins.linux.find_file as linux_find_file
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

try:
    import distorm3
    has_distorm = True
except ImportError:
    has_distorm = False

class linux_check_syscall(linux_common.AbstractLinuxCommand):
    """ Checks if the system call table has been altered """


    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('syscall-indexes', short_option = 'I', default = None, help = 'Path to unistd_{32,64}.h from the target machine', action = 'store', type = 'str')

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


    def _compute_hook_sym_name(self, visible_mods, hidden_mods, call_addr):
        mod_found = 0
        for (module, _, __) in visible_mods:
            if module.module_core <= call_addr <= module.module_core + module.core_size:
                mod_found = 1
                break

        if mod_found == 0:
            for module in hidden_mods:
                if module.module_core <= call_addr <= module.module_core + module.core_size:
                    mod_found = 1
                    break

        if mod_found == 1:        
            sym = module.get_symbol_for_address(call_addr)
            sym_name = "HOOKED: %s/%s" % (module.name, sym)
        else:    
            sym_name = "HOOKED: UNKNOWN"

        return sym_name

    def _index_name(self, index_names, i):
        if i in index_names:
            ret = index_names[i]
        else:
            ret = "<INDEX NOT FOUND %d>" % i
        
        return ret

    def _find_index(self, index_names, line_index):
        ret = None

        # "(__NR_timer_create+1)"
        (line_name, offset) = line_index[1:-1].split("+")
        line_name = line_name.replace("__NR_", "")

        for index in index_names:
            if index_names[index] == line_name:
                ret = index + int(offset)
                break

        if ret == None:
            debug.error("Unable to find offset for %s" % index_name)

        return ret

    def get_syscalls(self, index_lines = None, get_hidden = False):
        linux_common.set_plugin_members(self)

        if get_hidden:
            hidden_mods = list(linux_hidden_modules.linux_hidden_modules(self._config).calculate())
        else:
            hidden_mods = []    
    
        visible_mods = linux_lsmod.linux_lsmod(self._config).calculate()

        if not index_lines:
            index_lines = self._find_and_parse_index_file()

        if index_lines:
            index_names = {}
            for line in index_lines.split("\n"): 
                ents = line.split()

                if len(ents) == 3 and ents[0] == "#define":
                    name  = ents[1].replace("__NR_", "")

                    # "(__NR_timer_create+1)"
                    index = ents[2] 
                    if index[0] == "(":
                        index = self._find_index(index_names, index)
                    else:
                        try:
                            index = int(index)
                        except ValueError:
                            index = 999999  #well beyond any valid table index

                    index_names[index] = name
        else:
            index_names = None

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

                if index_names:
                    idx_name = self._index_name(index_names, i)
                else:
                    idx_name = ""

                call_addr = int(call_addr)

                if not call_addr in sym_addrs:
                    hooked = 1

                    sym_name = self._compute_hook_sym_name(visible_mods, hidden_mods, call_addr)
                else:
                    hooked = 0 
                    sym_name = self.profile.get_symbol_by_address("kernel", call_addr)

                yield (tableaddr, table_name, i, idx_name, call_addr, sym_name, hooked)
 
    def _find_and_parse_index_file(self):
        memory_model = self.addr_space.profile.metadata.get('memory_model', '32bit')

        if memory_model == '32bit':
            header_path = "unistd_32.h"
        else:
            header_path = "unistd_64.h"

        find_file = linux_find_file.linux_find_file(self._config)

        inodes = []
        for (_, _, file_path, file_dentry) in find_file.walk_sbs():
            ents = file_path.split("/") 
            if len(ents) > 1 and ents[-1] == header_path:
                inode = file_dentry.d_inode
                inodes.append(inode)

        ret = None
        for inode in inodes:
            buf = ""
            for page in find_file.get_file_contents(inode):
                buf = buf + page
            
            if len(buf) > 4096:
                ret = buf
                break

        return ret

    def calculate(self):
        """ 
        This works by walking the system call table 
        and verifies that each is a symbol in the kernel
        """
        linux_common.set_plugin_members(self)

        if not has_distorm:
            debug.warning("distorm not installed. The best method to calculate the system call table size will not be used.")
                        
        if self._config.SYSCALL_INDEXES:
            if not os.path.exists(self._config.SYSCALL_INDEXES):
                debug.error("Given syscall indexes file does not exist!")

            index_lines = open(self._config.SYSCALL_INDEXES, "r").read()
        else:
            index_lines = None

        for (tableaddr, table_name, i, idx_name, call_addr, sym_name, hooked) in self.get_syscalls(index_lines, True): 
            yield (tableaddr, table_name, i, idx_name, call_addr, sym_name, hooked)
 
    def unified_output(self, data):
        return TreeGrid([("TableName", str),
                       ("Index", int),
                       ("SystemCall", str),
                       ("HandlerAddress", Address),
                       ("Symbol", str)],
                        self.generator(data))

    def generator(self, data):
        for (tableaddr, table_name, i, idx_name, call_addr, sym_name, _) in data:
            yield (0, [str(table_name), int(i), str(idx_name), Address(call_addr), str(sym_name)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Table Name", "6"), ("Index", "5"), ("System Call", "24"), ("Handler Address", "[addrpad]"), ("Symbol", "<60")])
        for (tableaddr, table_name, i, idx_name, call_addr, sym_name, _) in data:
            self.table_row(outfd, table_name, i, idx_name, call_addr, sym_name)

