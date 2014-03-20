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
import volatility.utils as utils
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

extended_flags = {
    0x00000001 : "VM_READ",
    0x00000002 : "VM_WRITE",
    0x00000004 : "VM_EXEC",
    0x00000008 : "VM_SHARED",
    0x00000010 : "VM_MAYREAD",
    0x00000020 : "VM_MAYWRITE",
    0x00000040 : "VM_MAYEXEC",
    0x00000080 : "VM_MAYSHARE",
    0x00000100 : "VM_GROWSDOWN",
    0x00000200 : "VM_NOHUGEPAGE",
    0x00000400 : "VM_PFNMAP",
    0x00000800 : "VM_DENYWRITE",
    0x00001000 : "VM_EXECUTABLE",
    0x00002000 : "VM_LOCKED",
    0x00004000 : "VM_IO",
    0x00008000 : "VM_SEQ_READ",
    0x00010000 : "VM_RAND_READ",        
    0x00020000 : "VM_DONTCOPY", 
    0x00040000 : "VM_DONTEXPAND",
    0x00080000 : "VM_RESERVED",
    0x00100000 : "VM_ACCOUNT",
    0x00200000 : "VM_NORESERVE",
    0x00400000 : "VM_HUGETLB",
    0x00800000 : "VM_NONLINEAR",        
    0x01000000 : "VM_MAPPED_COP__VM_HUGEPAGE",
    0x02000000 : "VM_INSERTPAGE",
    0x04000000 : "VM_ALWAYSDUMP",
    0x08000000 : "VM_CAN_NONLINEAR",
    0x10000000 : "VM_MIXEDMAP",
    0x20000000 : "VM_SAO",
    0x40000000 : "VM_PFN_AT_MMAP",
    0x80000000 : "VM_MERGEABLE",
}

class linux_malfind(linux_pslist.linux_pslist):
    """Looks for suspicious process mappings"""

    def _parse_perms(self, flags):
        fstr = ""

        for mask in sorted(extended_flags.keys()):
            if flags & mask == mask:
                fstr = fstr + extended_flags[mask] + "|"
 
        if len(fstr) != 0:
            fstr = fstr[:-1]

        return fstr

    def _is_suspicious(self, vma):
        ret = False        

        flags_str = self._parse_perms(vma.vm_flags.v() & 0b1111)
        prot_str  = self._parse_perms(vma.vm_page_prot.v()) 
       
        if flags_str == "VM_READ|VM_WRITE|VM_EXEC":
           ret = True 
 
        return ret

    def _vma_name(self, task, vma):
        if vma.vm_file:
            fname = linux_common.get_path(task, vma.vm_file)
        elif vma.vm_start <= task.mm.start_brk and vma.vm_end >= task.mm.brk:
            fname = "[heap]"
        elif vma.vm_start <= task.mm.start_stack and vma.vm_end >= task.mm.start_stack:
            fname = "[stack]"
        else:
            fname = "Anonymous Mapping"

        return fname

    def render_text(self, outfd, data):
        for task in data:
            proc_as = task.get_process_address_space()

            for vma in task.get_proc_maps():

                if self._is_suspicious(vma):
                    fname = self._vma_name(task, vma)                    
                    prots = self._parse_perms(vma.vm_flags.v() & 0b1111) 
                    flags = self._parse_perms(vma.vm_flags.v())

                    content = proc_as.zread(vma.vm_start, 64)

                    outfd.write("Process: {0} Pid: {1} Address: {2:#x} File: {3}\n".format(
                        task.comm, task.pid, vma.vm_start, fname))

                    outfd.write("Protection: {0}\n".format(prots))

                    outfd.write("Flags: {0}\n".format(str(flags)))
                    outfd.write("\n")

                    outfd.write("{0}\n".format("\n".join(
                        ["{0:#010x}  {1:<48}  {2}".format(vma.vm_start + o, h, ''.join(c))
                        for o, h, c in utils.Hexdump(content)
                        ])))

                    outfd.write("\n")
                    outfd.write("\n".join(
                        ["{0:#x} {1:<16} {2}".format(o, h, i)
                        for o, i, h in malfind.Disassemble(content, vma.vm_start)
                        ]))
                
                    outfd.write("\n\n")

       


 
