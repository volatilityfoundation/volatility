# Volatility
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
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: 504ENSICS Labs
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_check_syscall_arm(linux_common.AbstractLinuxARMCommand):
    """ Checks if the system call table has been altered """
    
    def _get_syscall_table_size(self):
        """ Get size of syscall table from the vector_swi function """
    
        vector_swi_addr = self.addr_space.profile.get_symbol("vector_swi")
        
        max_opcodes_to_check = 1024
        while (max_opcodes_to_check):
            opcode = obj.Object("unsigned int", offset = vector_swi_addr, vm = self.addr_space)
            if ((opcode & 0xffff0000) == 0xe3570000):
                shift = 0x10 - ((opcode & 0xff00) >> 8)
                size = (opcode & 0xff) << (2 * shift)
                return size
                break
            vector_swi_addr += 4
            max_opcodes_to_check -= 1
            
        debug.error("Syscall table size could not be determined.")
        
    def _get_syscall_table_address(self):
        """ returns the address of the syscall table """
        syscall_table_address = self.addr_space.profile.get_symbol("sys_call_table")
        
        if syscall_table_address:
            return syscall_table_address
            
        #TODO: Handle event where this isn't exported (if needed)
        debug.error("Symbol sys_call_table not export.  Please file a bug report.")

    def calculate(self):
        """ 
        This works by walking the system call table 
        and verifies that each is a symbol in the kernel
        """
        linux_common.set_plugin_members(self)
        
        num_syscalls = self._get_syscall_table_size()
        syscall_addr = self._get_syscall_table_address()
        
        sym_addrs = self.profile.get_all_addresses()
        
        table = obj.Object("Array", offset = syscall_addr, vm = self.addr_space, targetType = "unsigned int", count = num_syscalls)
        
        for (i, call_addr) in enumerate(table):
            
            if not call_addr:
                continue

            # have to treat them as 'long' so need to mask
            call_addr = call_addr & 0xffffffff
                
            if not call_addr in sym_addrs:
                yield(i, call_addr, 1)
            else:
                yield(i, call_addr, 0)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Index", "[addr]"), ("Address", "[addrpad]"), ("Symbol", "<30")])
        for (i, call_addr, hooked) in data:

            if hooked == 0:
                sym_name = self.profile.get_symbol_by_address("kernel", call_addr)
            else:
                sym_name = "HOOKED"

            self.table_row(outfd, i, call_addr, sym_name)
