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

# based on the plugin described by Cem Gurkok at:
# http://siliconblade.blogspot.co.uk/2013/07/back-to-defense-finding-hooks-in-os-x.html

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import distorm3

import volatility.obj as obj
import volatility.plugins.mac.common as common
import volatility.debug as debug

class mac_check_syscall_shadow(common.AbstractMacCommand):
    """ Looks for shadow system call tables """

    # https://github.com/siliconblade/volatility/blob/master/mac/check_hooks.py#L216
    def shadowedSyscalls(self, model, distorm_mode, sysents_addr):
        #looks like these syscall functions end with a call to _thread_exception_return
        thread_exc_ret_addr = self.addr_space.profile.get_symbol('_thread_exception_return')

        prev_op = None
        sysent_funcs = ['_unix_syscall_return', '_unix_syscall64', '_unix_syscall']
        for func in sysent_funcs:
            func_addr = self.addr_space.profile.get_symbol(func)
            content = self.addr_space.read(func_addr, 1024)
            for op in distorm3.Decompose(func_addr, content, distorm_mode):
                if not op.valid:
                    break

                if op.mnemonic == "CALL" and op.operands[0].value == thread_exc_ret_addr:
                    break

                if model == "64bit":
                    #callp = &sysent[63] OR &sysent[code] OR callp == sysent
                    if op.mnemonic in ['ADD','CMP'] and op.operands[0].type == 'Register' and op.operands[0].name in ["RSP","RBX","R12","R13","R14","R15"] and 'FLAG_RIP_RELATIVE' in op.flags:
                        #compare actual sysent tbl address to the one in the instruction, calculated per distorm3 INSTRUCTION_GET_RIP_TARGET

                        op_sysent_ptr = obj.Object('Pointer', offset = (op.address + op.operands[1].disp + op.size), vm = self.addr_space)
 
                        if sysents_addr != op_sysent_ptr.v():
                            print "not same: %x | %x" % (sysents_addr, op_sysent_ptr.v())
                            yield (op_sysent_ptr.v(), func, op)
 
                elif model == "32bit":
                    #LEA EAX, [EAX*8+0x82ef20]
                    if op.mnemonic == 'LEA' and op.operands[0].type == 'Register' and op.operands[0].name in ['EDI','EAX'] and distorm3.Registers[op.operands[1].index] == "EAX" and op.operands[1].scale == 8:
                        if op.operands[1].disp != sysents_addr:
                            shadowtbl_addr = op.operands[1].disp
                            yield (shadowtbl_addr, func, op) 
                            break
                    #CMP EAX, 0x82ef20
                    elif op.mnemonic == 'CMP' and op.operands[0].type == 'Register' and op.operands[0].name in ['EDI','EAX'] and prev_op.mnemonic in ['LEA','MOV'] and self.addr_space.is_valid_address(op.operands[1].value) == True:
                        if op.operands[1].value != sysents_addr:
                            shadowtbl_addr = op.operands[1].value
                            yield (shadowtbl_addr, func, op)

                    #CMP DWORD [EBP-0x20], 0x82ef20
                    elif op.mnemonic == 'CMP' and op.operands[0].index != None and distorm3.Registers[op.operands[0].index] == "EBP" and op.operands[0].disp == -32 and op.operands[0].type == "Immediate":
                        if op.operands[1].value != sysents_addr:
                            shadowtbl_addr = op.operands[1].value
                            yield (shadowtbl_addr, func, op)
 
                prev_op = op

    def calculate(self):
        common.set_plugin_members(self)

        model = self.addr_space.profile.metadata.get('memory_model', 0)

        if model == '32bit':
            distorm_mode = distorm3.Decode32Bits
        else:
            distorm_mode = distorm3.Decode64Bits
        
        for (shadowtbl_addr, func, op) in self.shadowedSyscalls(model, distorm_mode, self.addr_space.profile.get_symbol("_sysent")):
            yield (shadowtbl_addr, func, op)

    def render_text(self, outfd, data):
        self.table_header(outfd, 
                          [("Hooked Function", "30"),
                          ("Hook Address", "[addrpad]"),
                          ("Instruction", "")])

        for (shadowtbl_addr, func, op) in data:
            self.table_row(outfd, func, shadowtbl_addr, op)

