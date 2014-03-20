# Volatility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
@author: Mariano `emdel` Graziano, Edwin Smulders
@license: GNU General Public License 2.0 or later
@contact: graziano@eurecom.fr, mail@edwinsmulders.eu
"""


import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.threads as linux_threads
import collections
import struct
import volatility.debug as debug

offsets = {}
# x86 offsets - It works on my Linux machine.
offsets['32bit'] = [
'ebx', 
'ecx',
'edx', 
'esi', 
'edi', 
'ebp', 
'eax', 
'ds', 
'es', 
'fs', 
'gs', 
'orig_eax', 
'eip', 
'cs', 
'eflags', 
'esp', 
'ss'
]

# x64 offsets
offsets['64bit'] = [
'r15', 
'r14', 
'r13', 
'r12',
'rbp', 
'rbx',
'r11', 
'r10', 
'r9', 
'r8',
'rax', 
'rcx', 
'rdx',
'rsi', 
'rdi',
'unknown', # I'm not sure what this field is
'rip',
'cs', 
'eflags', 
'rsp', 
'ss'
]

reg_size = {}
reg_size['32bit'] = 0x4
reg_size['64bit'] = 0x8

fmt = {}
fmt['32bit'] = '<I'
fmt['64bit'] = '<Q'


class linux_info_regs(linux_threads.linux_threads):
    '''It's like 'info registers' in GDB. It prints out all the
processor registers involved during the context switch.'''
    def __init__(self, config, *args, **kwargs):
        linux_threads.linux_threads.__init__(self, config, *args, **kwargs) 

        self.bits = self.profile.metadata.get('memory_model', '32bit')
        self.reg_size = reg_size[self.bits]
        self.offsets = offsets[self.bits]
        self.fmt = fmt[self.bits]

    def calculate(self):
        for task, (thread_group, threads) in linux_threads.linux_threads(self._config).calculate():
            name = task.get_commandline()
            thread_registers = []
            for thread_task in threads:
                thread_name = thread_task.comm
                regs = self.parse_kernel_stack(thread_task)
                thread_registers.append((thread_name,regs))
            yield task, name, thread_registers


    def render_text(self, outfd, data):

        #outfd.write("[-- Info Registers:\n")

        for task, name, thread_regs in data:
            outfd.write("Process Name: {} - PID: {}\n".format(name, str(task.pid)))
            outfd.write("Registers (per thread):\n")
            fmt = str(2*self.reg_size)
            for thread_name, regs in thread_regs:
                outfd.write("  Thread Name: {}\n".format(thread_name))
                if regs != None:
                    for reg, value in regs.items():

                        outfd.write(("    {:8s}: {:0" + fmt + "x}\n").format(reg, value))


    def parse_kernel_stack(self, task):
        result = collections.OrderedDict()
        if 1 or task.mm:
            sp0 = task.thread.sp0
            #proc_as = task.get_process_address_space()
            addr = sp0

            for reg in self.offsets[::-1]: # reverse list, because we read up in the stack
                #debug.info("Reading {:016x}".format(addr))
                addr -= self.reg_size
                val_raw = self.addr_space.read(addr, self.reg_size)
                val = struct.unpack(self.fmt, val_raw)[0]
                result[reg] = val
            return result
        return None
