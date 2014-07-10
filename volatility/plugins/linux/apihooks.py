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

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.plthook as linux_plthook
import volatility.plugins.linux.pslist as linux_pslist

import distorm3

class linux_apihooks(linux_pslist.linux_pslist):
    """Checks for userland apihooks"""

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option( \
                'ALL', short_option = 'a', default = False,
                help = 'Check all functions, including those with PLT hooks', action = 'store_true')
    
    def _is_hooked(self, sym_addr, proc_as):
        hook_type = None 
        addr = None    
        counter   = 1 
        prev_op = None

        if self.profile.metadata.get('memory_model', '32bit') == '32bit':
            mode = distorm3.Decode32Bits
        else:
            mode = distorm3.Decode64Bits

        data = proc_as.read(sym_addr, 24)
    
        for op in distorm3.Decompose(sym_addr, data, mode):
            if not op or not op.valid:
                continue

            if op.mnemonic == "JMP":
                hook_type = "JMP"
                addr = 0 # default in case we cannot extract               

                # check for a mov reg, addr; jmp reg;
                if prev_op and prev_op.mnemonic == "MOV" and prev_op.operands[0].type == 'Register' and op.operands[0].type == 'Register':
                    prev_name = prev_op.operands[0].name
                    
                    # same register
                    if prev_name == op.operands[0].name:
                        addr = prev_op.operands[1].value                        

                else:
                    addr = op.operands[0].value

            elif op.mnemonic == "CALL":
                hook_type = "CALL"
                addr = op.operands[0].value

            # push xxxx; ret;
            elif counter == 2 and op.mnemonic == "RET":
                if prev_op.mnemonic == "MOV" and prev_op.operands[0].type == 'Register' and  prev_op.operands[0].name in ["RAX", "EAX"]:
                    break

                elif prev_op.mnemonic == "XOR" and prev_op.operands[0].type == 'Register' and prev_op.operands[1].type == 'Register':
                    break

                elif prev_op.mnemonic == "MOV" and prev_op.operands[0].type == 'Register' and  prev_op.operands[1].type == 'Register':
                    break
                
                hook_type = "RET"
                addr = sym_addr

            if hook_type:
                break

            counter = counter + 1
            if counter == 4:
                break

            prev_op = op

        if hook_type:
            ret = hook_type, addr
        else:
            ret = None

        return ret

    def _get_name(self, task, addr):
        hook_vma = None        
        hookdesc = "<Unknown mapping>"

        for i in task.get_proc_maps():
            if addr >= i.vm_start and addr < i.vm_end:
                hook_vma = i
                break          
          
        if hook_vma:
            if hook_vma.vm_file:
                hookdesc = linux_common.get_path(task, hook_vma.vm_file)
            else:
                hookdesc = '[{0:x}:{1:x},{2}]'.format(hook_vma.vm_start, hook_vma.vm_end, hook_vma.vm_flags)
        
        return (hook_vma, hookdesc)

    def calculate(self):
        linux_common.set_plugin_members(self)

        for task, soname, elf, elf_start, elf_end, addr, symbol_name, _, plt_hooked in linux_plthook.linux_plthook(self._config).calculate():
                # this would lead us to the malware's function...
                if plt_hooked and not self._config.ALL:
                    continue
                   
                is_hooked = self._is_hooked(addr, elf.obj_vm)

                if is_hooked:
                    hook_type, hook_addr = is_hooked
                else:
                    continue

                (hook_vma, hookdesc) = self._get_name(task, addr)
                (hook_func_vma, hookfuncdesc) = self._get_name(task, hook_addr)

                if not hook_vma or not hook_func_vma or hook_vma.vm_start != hook_func_vma.vm_start:
                    yield task, hookdesc, symbol_name, addr, hook_type, hook_addr, hookfuncdesc

    def render_text(self, outfd, data):
        self.table_header(outfd, [
                                  ("Pid", "7"),
                                  ("Name", "16"),
                                  ("Hook VMA", "40"),
                                  ("Hook Symbol", "24"),
                                  ("Hooked Address", "[addrpad]"),
                                  ("Type", "5"),
                                  ("Hook Address", "[addrpad]"),                    
                                  ("Hook Library", ""),
                                  ]) 

        for task, hook_desc, sym_name, addr, hook_type, hook_addr, hookfuncdesc in data:
            self.table_row(outfd, task.pid, task.comm, hook_desc, sym_name, addr, hook_type, hook_addr, hookfuncdesc)



