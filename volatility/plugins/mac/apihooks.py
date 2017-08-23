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
import volatility.plugins.mac.pstasks as pstasks 
import volatility.plugins.mac.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

import distorm3

class mac_apihooks(pstasks.mac_tasks):
    """ Checks for API hooks in processes """

    def __init__(self, config, *args, **kwargs):
        self.mapping_cache = {}

        pstasks.mac_tasks.__init__(self, config, *args, **kwargs)
  
    def _is_api_hooked(self, sym_addr, proc_as):
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

    def _fill_mapping_cache(self, proc):
        proc_as = proc.get_process_address_space()
            
        self.mapping_cache[proc.v()] = {}
            
        ranges = []

        for mapping in proc.get_dyld_maps():
            m = obj.Object("macho_header", offset = mapping.imageLoadAddress, vm = proc_as)        
        
            for seg in m.segments():
                ranges.append((mapping.imageFilePath, seg.vmaddr, seg.vmaddr + seg.vmsize))

        self.mapping_cache[proc.v()] = ranges 

    def _find_mapping(self, proc, addr):
        ret =  None

        if not proc.v() in self.mapping_cache:
            self._fill_mapping_cache(proc)

        mappings = self.mapping_cache[proc.v()]

        for (path, start, end) in mappings:
            if start <= addr <= end:
                ret = (path, start, end)
                break

        return ret 

    def _find_mapping_proc_maps(self, proc, addr):
        ret = None

        for mapping in proc.get_proc_maps():
            if mapping.start <= addr <= mapping.end:
                ret = (mapping.get_path(), mapping.start, mapping.end)

        return ret
    
    def calculate(self):
        common.set_plugin_members(self)

        procs = pstasks.mac_tasks(self._config).calculate()

        for proc in procs:
            proc_as = proc.get_process_address_space()

            for mapping in proc.get_dyld_maps():
                path = mapping.imageFilePath

                macho = obj.Object("macho_header", offset = mapping.imageLoadAddress, vm = proc_as)

                needed_libraries = {}
                for n in macho.needed_libraries():
                    needed_libraries[n] = 1 

                for (name, addr) in macho.imports():
                    is_lazy       = False
                    is_ptr_hooked = False
                    is_api_hooked = False
                    hook_addr = 0
                    hook_type = ""

                    vma_mapping = self._find_mapping(proc, addr)
                    if vma_mapping == None:
                        vma_mapping = self._find_mapping_proc_maps(proc, addr)

                    if vma_mapping:
                        (vma_path, vma_start, vma_end) = vma_mapping
                    else:
                        # the address points to a bogus (non-mapped region)
                        vma_path = "<UNKNOWN>"
                        vma_start = addr
                        vma_end = addr  

                    addr_mapping = vma_path

                    # non-resolved symbols
                    if vma_start <= mapping.imageLoadAddress <= vma_end:
                        is_lazy = True                        
                    else:
                        is_ptr_hooked = not addr_mapping in needed_libraries

                        # check if pointing into the shared region
                        # this happens as libraries in the region are not listed as needed
                        if is_ptr_hooked:
                            if proc.task.shared_region.sr_base_address <= addr <= proc.task.shared_region.sr_base_address + proc.task.shared_region.sr_size:
                                is_ptr_hooked = False
    
                        if not is_ptr_hooked:
                            is_api_hooked = self._is_api_hooked(addr,  proc_as)  
                            if is_api_hooked:
                                (hook_type, hook_addr) = is_api_hooked

                    yield (proc, name, addr, is_lazy, is_ptr_hooked, is_api_hooked, hook_type, hook_addr, addr_mapping)

    def unified_output(self, data):
        return TreeGrid([("Name", str),
                        ("PID", int),
                        ("Symbol", str),
                        ("Sym Address", Address),
                        ("Lazy", str),
                        ("Ptr Hook", str),
                        ("API Hook", str),
                        ("Hook Type", str),
                        ("Hook Addr", Address),
                        ("Hook Library", str),
                        ], self.generator(data))

    def generator(self, data):
        for (task, name, addr, is_lazy, is_ptr_hooked, is_api_hooked, hook_type, hook_addr, addr_mapping) in data:
            if is_lazy:
                is_lazy = "True"
            else:
                is_lazy = "False"

            if is_ptr_hooked:
                is_ptr_hooked = "True"
            else:
                is_ptr_hooked = "False"

            if is_api_hooked:
                is_api_hooked = "True"
            else:
                is_api_hooked = "False"

            yield(0, [
                str(task.p_comm),
                int(task.p_pid),
                str(name),
                Address(addr),
                str(is_lazy),
                str(is_ptr_hooked),
                str(is_api_hooked),
                str(hook_type),
                Address(hook_addr),
                str(addr_mapping),
                ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "16"),
                                  ("PID", "6"),
                                  ("Symbol", "25"),
                                  ("Sym Address", "[addrpad]"),
                                  ("Lazy", "5"),
                                  ("Ptr Hook", "6"),
                                  ("API Hook", "6"),
                                  ("Hook Type", "6"),
                                  ("Hook Addr", "[addrpad]"),
                                  ("Hook Library", ""),
                                 ])       
 
        for (task, name, addr, is_lazy, is_ptr_hooked, is_api_hooked, hook_type, hook_addr, addr_mapping) in data:
            if is_lazy:
                is_lazy = "True"
            else:
                is_lazy = "False"

            if is_ptr_hooked:
                is_ptr_hooked = "True"
            else:
                is_ptr_hooked = "False"

            if is_api_hooked:
                is_api_hooked = "True"
            else:
                is_api_hooked = "False"

            self.table_row(outfd, task.p_comm, task.p_pid, name, addr, is_lazy, is_ptr_hooked, is_api_hooked, hook_type, hook_addr, addr_mapping)
