# Volatility
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
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: 504ENSICS Labs
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_check_evt_arm(linux_common.AbstractLinuxARMCommand):
    ''' Checks the Exception Vector Table to look for syscall table hooking '''

    VECTOR_BASE = 0xffff0000
    SWI_BASE = VECTOR_BASE + 8
        
    def calculate(self):
        linux_common.set_plugin_members(self)
        # Get instructions executed when an inturrupt exception occurs
        swi = obj.Object("unsigned int", offset = self.SWI_BASE, vm = self.addr_space)
        
        # Get offset of address to vector_swi
        offset = (swi & 0x0fff) + 8
        
        # Verify that instruction hasn't been modified (should be: ldr pc, [pc, #???] (e59ff???))
        if (swi & 0xfffff000) == 0xe59ff000:
            yield ("SWI Offset Instruction", "PASS", "Offset: {0}".format(offset))
        else:
            yield ("SWI Offset Instruction", "FAIL", "{0:X}".format(swi))
            return
        
        # Get vector_swi_addr from table
        vector_swi_addr = obj.Object("unsigned int", offset = self.SWI_BASE + (offset), vm = self.addr_space)
        
        # Check to see if vector_swi handler has been hooked
        if vector_swi_addr == self.addr_space.profile.get_symbol("vector_swi"):
            yield ("vector_swi address", "PASS", "0x{0:X}".format(vector_swi_addr))
        else:
            yield ("vector_swi address", "FAIL", "0x{0:X}".format(vector_swi_addr))
            return
            
        # Check for hooking of sys_call table pointer
        sc_opcode = None;
        max_opcodes_to_check = 1024
        while (max_opcodes_to_check):
            opcode = obj.Object("unsigned int", offset=  vector_swi_addr, vm = self.addr_space)
            if ((opcode & 0xffffff00) == 0xe28f8000):
                sc_opcode = opcode
                break
            vector_swi_addr += 4
            max_opcodes_to_check -= 1
            
        if sc_opcode:
            yield ("vector_swi code modification", "PASS", "{0:X}".format(sc_opcode))
        else:
            yield ("vector_swi code modification", "FAIL", "Opcode E28F80?? not found")
            return
          
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Check", "<30"), ("PASS/FAIL", "<5"), ("Info", "<30")])
        for (check, result, info) in data:
            self.table_row(outfd, check, result, info)
