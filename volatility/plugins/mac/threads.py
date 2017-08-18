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
@author:       Cem Gurkok
@license:      GNU General Public License 2.0
@contact:      cemgurkok@gmail.com
@organization:
"""
import volatility.obj as obj
import volatility.plugins.mac.common as common
import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.mac.pstasks as mac_tasks
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

## http://hte.sourceforge.net/doxygenized-0.8.0pre1/machostruc_8h-source.html
## documentation for thread state, registry, launch cmd etc

thread_overlay = {
                     "thread": [ None, {
                                            "options": [None, ['Flags', {'target': 'int', 'bitmap': {    
                                                                                                          "TH_OPT_INTMASK": 0,# interrupt / abort level 
                                                                                                          "TH_OPT_INTMASK": 1,# interrupt / abort level 
                                                                                                          "TH_OPT_VMPRIV": 2, # may allocate reserved memory
                                                                                                          "TH_OPT_DTRACE": 3, # executing under dtrace_probe
                                                                                                          "TH_OPT_SYSTEM_CRITICAL": 4, # Thread must always be allowed to run, even under heavy load 
                                                                                                          "TH_OPT_PROC_CPULIMIT": 5, # Thread has a task-wide CPU limit applied to it 
                                                                                                          "TH_OPT_PRVT_CPULIMIT": 6 # Thread has a thread-private CPU limit applied to it
                                                                       }}]],
                                            "state":   [None, ['Flags', {'target': 'int', 'bitmap': {
                                                                                                          "TH_WAIT": 0,
                                                                                                          "TH_SUSP": 1,
                                                                                                          "TH_RUN": 2,
                                                                                                          "TH_UNINT": 3,
                                                                                                          "TH_TERMINATE": 4,
                                                                                                          "TH_TERMINATE2": 5,
                                                                                                          "TH_IDLE": 6, # kAppleProfileTriggerClientThreadModeIdle
                                                                                                          "TH_IDLE_N": 6 << 16 # kAppleProfileTriggerClientThreadModeNotIdle, !TH_IDLE
                                                                       }}]],
                                            "sched_mode": [None, ['Flags', {'target': 'int', 'bitmap': {
                                                                                                          "TH_MODE_REALTIME": 0,  # /* time constraints supplied */
                                                                                                          "TH_MODE_TIMESHARE": 1, # /* use timesharing algorithm */
                                                                                                          "TH_MODE_FAILSAFE": 2,  # /* fail-safe has tripped */
                                                                                                          "TH_MODE_PROMOTED": 3,  # /* sched pri has been promoted */
                                                                                                          "TH_MODE_ABORT": 4,     # /* abort interruptible waits */
                                                                                                          "TH_MODE_ABORTSAFELY": 5, # /* ... but only those at safe point */
                                                                                                          # "TH_MODE_ISABORTED": (TH_MODE_ABORT | TH_MODE_ABORTSAFELY) 
                                                                                                          "TH_MODE_DEPRESS": 6,   # /* normal depress yield */
                                                                                                          "TH_MODE_POLLDEPRESS": 7, # /* polled depress yield */
                                                                                                          # "TH_MODE_ISDEPRESSED": (TH_MODE_DEPRESS | TH_MODE_POLLDEPRESS)
                                                                       }}]],
                                            "ast": [None, ['Flags', {'target': 'int', 'bitmap': { # Asynchronous System Traps
                                                                                                          # AST_NONE , no bits set
                                                                                                          "AST_HALT": 0,
                                                                                                          "AST_TERMINATE": 1,
                                                                                                          "AST_BLOCK": 2,
                                                                                                          "AST_UNUSED": 3,
                                                                                                          "AST_QUANTUM": 4,
                                                                                                          "AST_APC": 5, # /* migration APC hook */
                                                                                                          "AST_URGENT": 6
                                                                       }}]],

                     }]
                 }

class queue_entry(obj.CType):
    # needed a separate walk_list function for threads since the original was task specific
    def thread_walk_list(self, list_head):
        n = self.next.dereference_as("thread")
        while n and n.obj_offset != list_head:
            yield n
            n = n.task_threads.next.dereference_as("thread")
        p = self.prev.dereference_as("thread")
        while p and p.obj_offset != list_head:
            yield p
            p = p.task_threads.prev.dereference_as("thread")

    def walk_list(self, list_head):
        n = self.next.dereference_as("task")
        while n and n.obj_offset != list_head:
            yield n
            n = n.tasks.next.dereference_as("task")
        p = self.prev.dereference_as("task")
        while p and p.obj_offset != list_head:
            yield p
            p = p.tasks.prev.dereference_as("task")

class MacObjectClasses2(obj.ProfileModification):

    conditions = {'os': lambda x: x == 'mac'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.object_classes.update({
            'queue_entry' : queue_entry
        })

class MacObjectClasses4(obj.ProfileModification):

    conditions = {'os': lambda x: x == 'mac'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.merge_overlay(thread_overlay)

# https://www.opensource.apple.com/source/xnu/xnu-124.1/osfmk/mach/vm_statistics.h
dict_alias = {
    1: "VM_MEMORY_MALLOC",
    2: "VM_MEMORY_MALLOC_SMALL",
    3: "VM_MEMORY_MALLOC_LARGE",
    4: "VM_MEMORY_MALLOC_HUGE",
    5: "VM_MEMORY_SBRK",
    6: "VM_MEMORY_REALLOC",
    7: "VM_MEMORY_MALLOC_TINY",
    8: "VM_MEMORY_MALLOC_LARGE_REUSABLE",
    9: "VM_MEMORY_MALLOC_LARGE_REUSED",
    10: "VM_MEMORY_ANALYSIS_TOOL",
    20: "VM_MEMORY_MACH_MSG",
    21: "VM_MEMORY_IOKIT",
    30: "VM_MEMORY_STACK",
    31: "VM_MEMORY_GUARD",
    32: "VM_MEMORY_SHARED_PMAP",
    33: "VM_MEMORY_DYLIB",
    34: "VM_MEMORY_OBJC_DISPATCHERS",
    35: "VM_MEMORY_UNSHARED_PMAP",
    40: "VM_MEMORY_APPKIT",
    41: "VM_MEMORY_FOUNDATION",
    42: "VM_MEMORY_COREGRAPHICS",
    43: "VM_MEMORY_CORESERVICES",
    44: "VM_MEMORY_JAVA",
    50: "VM_MEMORY_ATS",
    51: "VM_MEMORY_LAYERKIT",
    52: "VM_MEMORY_CGIMAGE",
    53: "VM_MEMORY_TCMALLOC",
    54: "VM_MEMORY_COREGRAPHICS_DATA",
    55: "VM_MEMORY_COREGRAPHICS_SHARED",
    56: "VM_MEMORY_COREGRAPHICS_FRAMEBUFFERS",
    57: "VM_MEMORY_COREGRAPHICS_BACKINGSTORES",
    60: "VM_MEMORY_DYLD",
    61: "VM_MEMORY_DYLD_MALLOC",
    62: "VM_MEMORY_SQLITE",
    63: "VM_MEMORY_JAVASCRIPT_CORE",
    64: "VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR",
    65: "VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE",
    66: "VM_MEMORY_GLSL",
    67: "VM_MEMORY_OPENCL",
    68: "VM_MEMORY_COREIMAGE",
    69: "VM_MEMORY_WEBCORE_PURGEABLE_BUFFERS",
    70: "VM_MEMORY_IMAGEIO",
    71: "VM_MEMORY_COREPROFILE",
    72: "VM_MEMORY_ASSETSD",
    240: "VM_MEMORY_APPLICATION_SPECIFIC_1",
    241: "VM_MEMORY_APPLICATION_SPECIFIC_2",
    242: "VM_MEMORY_APPLICATION_SPECIFIC_3",
    243: "VM_MEMORY_APPLICATION_SPECIFIC_4",
    244: "VM_MEMORY_APPLICATION_SPECIFIC_5",
    245: "VM_MEMORY_APPLICATION_SPECIFIC_6",
    246: "VM_MEMORY_APPLICATION_SPECIFIC_7",
    247: "VM_MEMORY_APPLICATION_SPECIFIC_8",
    248: "VM_MEMORY_APPLICATION_SPECIFIC_9",
    249: "VM_MEMORY_APPLICATION_SPECIFIC_10",
    250: "VM_MEMORY_APPLICATION_SPECIFIC_11",
    251: "VM_MEMORY_APPLICATION_SPECIFIC_12",
    252: "VM_MEMORY_APPLICATION_SPECIFIC_13",
    253: "VM_MEMORY_APPLICATION_SPECIFIC_14",
    254: "VM_MEMORY_APPLICATION_SPECIFIC_15",
    255: "VM_MEMORY_APPLICATION_SPECIFIC_16"
}



class mac_threads(mac_tasks.mac_tasks):
    """ List Process Threads """

    def get_active_threads(self):
        threads = {}
        real_ncpus = obj.Object("int", offset = self.addr_space.profile.get_symbol("_real_ncpus"), vm = self.addr_space)
        cpu_data_ptrs = obj.Object(theType = 'Array', offset = self.addr_space.profile.get_symbol("_cpu_data_ptr"), vm = self.addr_space, targetType = "unsigned long long", count = real_ncpus)
        for i in range(0, real_ncpus):
            cpu_data = obj.Object('cpu_data', offset = cpu_data_ptrs[i], vm = self.addr_space)
            threads[i] = cpu_data.cpu_active_thread

        return threads

    def is_thread_active(self, thread, active_threads):
        for active_thread in active_threads.values():
            if active_thread.v() == thread.v():
                return True
        return False

    def get_stack_map(self, proc, proc_threads, bit_string):
        proc_addrspace = proc.get_process_address_space()
        vm_map_slide = 0
        vm_map_start = 0
        stack_thread_id = None
        maps = []

        for map in proc.get_proc_maps():
            vm_map_start = map.links.start
            map_type = str(dict_alias.get(int(map.range_alias()), "UNKNOWN"))
            map_path = map.get_path()

            # see if map is a STACK (not a STACK_GUARD), if so which thread it belongs to

            # VM_MEMORY_STACK
            if map_type == "VM_MEMORY_STACK" and map.get_perms() != "---":

                for thread in proc_threads:
                    # 64bit thread
                    if "64" in bit_string:
                        # isf: interrupt stack frame
                        thread_sp = thread.machine.iss.uss.ss_64.isf.rsp
                    # 32 bit thread
                    else:
                        thread_sp = thread.machine.iss.uss.ss_32.uesp

                    if map.links.start <= thread_sp and thread_sp <= map.links.end:
                        stack_thread_id = thread.thread_id
                        map_path = "thread id {0}".format(thread.thread_id)
                        break

                if "thread" in map_path:
                # Based on the vmmap command:
                 # current map is a stack marked as thread, then mark previous map with thread id if stack
                    prev_proc, prev_map, prev_map_path = maps.pop()
                    if str(dict_alias.get(int(prev_map.range_alias()), "UNKNOWN")) == "VM_MEMORY_STACK" and prev_map.get_perms() != "---" and "thread" not in prev_map_path:
                        prev_map_path = "thread id {0}".format(stack_thread_id)
                    maps.append((prev_proc, prev_map, prev_map_path))
                else:
                 # if previous map is a stack marked as thread, then mark current map with thread id
                    prev_proc, prev_map, prev_map_path = maps.pop()
                    if str(dict_alias.get(int(prev_map.range_alias()), "UNKNOWN")) == "VM_MEMORY_STACK" and prev_map.get_perms() != "---" and "thread" in prev_map_path:
                        map_path = "thread id {0}".format(stack_thread_id)
                    maps.append((prev_proc, prev_map, prev_map_path))

            elif map_type != "VM_MEMORY_STACK":
                stack_thread_id = None

            maps.append((proc, map, map_path))

        return maps

    def get_thread_registers(self, thread, bit_string):
        # http://www.opensource.apple.com/source/xnu/xnu-2050.18.24/osfmk/i386/pcb.c
        registers_64 = ['rdi','rsi','rdx','rbp','rbx','rcx','rax','cr2','r8','r9','r10','r11','r12','r13','r14','r15','gs','fs']
        registers_32 = ['edi','esi','edx','ebp','ebx','uesp','ecx','eax','eip','cr2','gs','cs','fs','es','ds']
        registers = {}

        if "64" in bit_string:
            registers['rsp'] = "{0:#10x}".format(getattr(thread.machine.iss.uss.ss_64.isf, 'rsp'))
            registers['rip'] = "{0:#10x}".format(getattr(thread.machine.iss.uss.ss_64.isf, 'rip'))
            registers['ss'] = "{0:#10x}".format(getattr(thread.machine.iss.uss.ss_64.isf, 'ss'))
            registers['trapno'] = "{0:#10x}".format(getattr(thread.machine.iss.uss.ss_64.isf, 'trapno'))

            # check if trap function/sysent is known or hooked
            trapfn_addr = getattr(thread.machine.iss.uss.ss_64.isf, 'trapfn')

            if trapfn_addr == 0:
                trapfn_name = ''
            else:
                trapfn_name = self.addr_space.profile.get_symbol_by_address('kernel', trapfn_addr)

            if trapfn_name == '':
                trapfn = "UNKNOWN function at {0}".format(trapfn_addr) 
            else:
                trapfn = "{0} at {1:#10x}".format(trapfn_name, trapfn_addr)

            registers['trapfn'] = trapfn

            for reg in registers_64:
                registers[reg] = "{0:#10x}".format(getattr(thread.machine.iss.uss.ss_64, reg))
        else:
            for reg in registers_32:
                if hasattr(thread.machine, "iss"):
                    registers[reg] = "{0:#10x}".format(getattr(thread.machine.iss.uss.ss_32, reg))
                else:
                    registers[reg] = ""

        return registers

    def calculate(self):
        common.set_plugin_members(self)

        for proc in mac_tasks.mac_tasks(self._config).calculate():
            bit_string = str(proc.task.map.pmap.pm_task_map or '')[9:]

            # get proc args and arg address
            args = proc.get_arguments()
            args_addr = proc.user_stack - proc.p_argslen

            # get threads
            qentry = proc.task.threads
            seen_threads = []
            thread_list = []
            active_threads = self.get_active_threads()

            for thread in qentry.thread_walk_list(qentry.obj_offset):
                if thread.obj_offset not in seen_threads:
                    seen_threads.append(thread.obj_offset)
                    thread_list.append(thread)

            # get proc maps
            maps = self.get_stack_map(proc, thread_list, bit_string)
            # get thread stack start and size
            for thread in thread_list:
                stack_start  = 0
                stack_size   = 0
                thread_args  = ""
                registers    = {}
                is_active    = "NO"
                dtraced      = "NO"
                debugged     = "NO"
                uid          = "NONE"

                for proc, map, map_path in maps:
                    if "thread id {0}".format(thread.thread_id) in map_path:
                        if stack_start == 0 or stack_start > map.links.start:
                            stack_start = map.links.start
                        stack_size += map.links.end - map.links.start
                        # find thread with args, which probably is main thread
                        if map.links.start < args_addr < map.links.end:
                            thread_args = args

                # kernel_stack process
                # thread stack information is empty for kernel threads
                if str(proc.p_pid) == "0":
                    stack_start = thread.kernel_stack

                registers = self.get_thread_registers(thread, bit_string)
                if self.is_thread_active(thread, active_threads):
                    is_active = "YES"

                # check if thread is being hardware debugged, ids = x86_debug_state64
                if thread.machine.ids != 0:
                    debugged = "YES"

                # check if dtrace probe is applied
                if "TH_OPT_DTRACE" in str(thread.options):
                    dtraced = "YES"

                #get thread User ID
                #if thread.uthread != 0:
                #uid = thread.uthread.dereference_as('uthread').uu_context.vc_ucred.cr_posix.cr_uid

                yield proc, thread, stack_start, stack_size, thread_args, registers, is_active, dtraced, debugged, uid

            proc = proc.p_list.le_next.dereference()
        
        self.get_active_threads()

    def unified_output(self, data):
        return TreeGrid([("Offset", Address),
                                  ("Pid", int),
                                  ("Tid", int),
                                  ("UID", str),
                                  ("State", str),
                                  ("Is Active?", str),
                                  ("Options", str),
                                  ("Priority", int),
                                  ("Startup Addr", Address),
                                  ("Stack Start Addr", Address),
                                  ("Stack Size (bytes)", int),
                                  ("HW Debugged",str),
                                  ("DTraced", str),
                                  ("Arguments", str),
                                  ], self.generator(data))
                          
    def generator(self, data):
        for proc, thread, stack_start, stack_size, args, registers, is_active, dtraced, debugged, uid in data:
            if not thread.is_valid():
                continue

            yield (0, [
                        Address(thread.v()),
                        int(proc.p_pid),
                        int(thread.thread_id),
                        str(uid),
                        str(thread.state),
                        str(is_active),
                        str(thread.options),
                        int(thread.sched_pri),
                        Address(thread.continuation),
                        Address(stack_start),
                        int(stack_size),
                        str(debugged),
                        str(dtraced),
                        str(args),
                        ])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Pid", "8"),
                                  ("Tid", "8"),
                                  ("UID", "8"),
                                  ("State", "30"),
                                  ("Is Active?","<10"),
                                  ("Options", "30"),
                                  ("Priority", "8"),
                                  ("Startup Addr", "[addrpad]"),
                                  ("Stack Start Addr", "[addrpad]"),
                                  ("Stack Size (bytes)", "<18"),
                                  ("HW Debugged","<11"),
                                  ("DTraced","<7"),
                                  ("Arguments", "")
                          ])

        for proc, thread, stack_start, stack_size, args, registers, is_active, dtraced, debugged, uid in data:
            if not thread.is_valid():
                continue

            self.table_row(outfd, thread.v(),
                                  str(proc.p_pid),
                                  str(thread.thread_id),
                                  str(uid),
                                  str(thread.state),
                                  is_active,
                                  str(thread.options),
                                  str(thread.sched_pri),
                                  thread.continuation,
                                  stack_start,
                                  stack_size,
                                  debugged,
                                  dtraced,
                                  args
                           )
            #for reg in registers:
            #    outfd.write("\t{0:<10} {1:}\n".format(reg, registers[reg].strip()))
