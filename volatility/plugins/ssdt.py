# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

from operator import itemgetter

import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.plugins.malware.apihooks as apihooks
import volatility.debug as debug #pylint: disable-msg=W0611
from volatility.cache import CacheDecorator
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

#pylint: disable-msg=C0111

def find_tables(nt_base, start_addr, vm):
    """
    This function finds the RVAs to KeServiceDescriptorTable
    and KeServiceDescriptorTableShadow in the NT module. 

    @param start_addr: virtual address of KeAddSystemServiceTable
    @param vm: kernel address space 

    We're looking for two instructions like this:

    //if (KeServiceDescriptorTable[i].Base)
    4B 83 BC 1A 40 88 2A 00 00    cmp qword ptr [r10+r11+2A8840h], 0 
    //if (KeServiceDescriptorTableShadow[i].Base)
    4B 83 BC 1A 80 88 2A 00 00    cmp qword ptr [r10+r11+2A8880h], 0

    In the example, 2A8840h is the RVA of KeServiceDescriptorTable 
    and 2A8880h is the RVA of KeServiceDescriptorTableShadow. The
    exported KeAddSystemServiceTable is a very small function (about
    120 bytes at the most) and the two instructions appear very 
    early, which reduces the possibility of false positives. 

    If distorm3 is installed, we use it to decompose instructions 
    in x64 format. If distorm3 is not available, we use Volatility's
    object model as a very simple and generic instruction parser. 
    """
    service_tables = []

    try:
        import distorm3
        use_distorm = True
    except ImportError:
        use_distorm = False

    function_size = 120

    if use_distorm:
        data = vm.zread(start_addr, function_size)
        for op in distorm3.DecomposeGenerator(start_addr, data, distorm3.Decode64Bits):
            # Stop decomposing if we reach the function end 
            if op.flowControl == 'FC_RET':
                break
            # Looking for a 9-byte CMP instruction whose first operand
            # has a 32-bit displacement and second operand is zero or
            # a 7-byte CMP instruction with RIP relative addressing
            if op.mnemonic == 'CMP' and op.operands[0].dispSize == 32 and op.operands[0].value == 0:
                if op.size == 9:
                    service_tables.append(nt_base + op.operands[0].disp)
                elif op.size in [7, 8]:
                    service_tables.append(op.address + op.size + op.operands[0].disp)
            elif op.mnemonic == 'LEA' and op.size == 7 and op.operands[1].dispSize == 32 and op.operands[1].disp > 0:
                service_tables.append(nt_base + op.operands[1].disp)
    else:
        vm.profile.add_types({
            '_INSTRUCTION' : [ 9, {
            'opcode' : [ 0, ['String', dict(length = 4)]],
            'disp'   : [ 4, ['int']],
            'value'  : [ 8, ['unsigned char']],
        }]})
        # The variations assume (which happens to be correct on all OS)
        # that volatile registers are used in the CMP QWORD instruction.
        # All combinations of volatile registers (rax, rcx, rdx, r8-r11)
        # will result in one of the variations in this list. 
        ops_list = [
            "\x4B\x83\xBC", # r10, r11
            "\x48\x83\xBC", # rax, rcx
            "\x4A\x83\xBC", # rax, r8
            "\x48\x8D\x8B", # win8x64 LEA RCX, [EBX+??????]
        ]
        for i in range(function_size):
            op = obj.Object("_INSTRUCTION", offset = start_addr + i, vm = vm)
            if op.value == 0:
                for s in ops_list:
                    if op.opcode.v().startswith(s):
                        service_tables.append(nt_base + op.disp)

    return service_tables

class SSDT(common.AbstractWindowsCommand):
    "Display SSDT entries"
    # Declare meta information associated with this plugin
    meta_info = {
        'author': 'Brendan Dolan-Gavitt',
        'copyright': 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        'contact': 'bdolangavitt@wesleyan.edu',
        'license': 'GNU General Public License 2.0',
        'url': 'http://moyix.blogspot.com/',
        'os': 'WIN_32_XP_SP2',
        'version': '1.0'}

    @CacheDecorator("tests/ssdt")
    def calculate(self):
        addr_space = utils.load_as(self._config)

        ## Get a sorted list of module addresses
        mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in modules.lsmod(addr_space))
        mod_addrs = sorted(mods.keys())

        ssdts = set()

        if addr_space.profile.metadata.get('memory_model', '32bit') == '32bit':
            # Gather up all SSDTs referenced by threads
            print "[x86] Gathering all referenced SSDTs from KTHREADs..."
            for proc in tasks.pslist(addr_space):
                for thread in proc.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
                    ssdt_obj = thread.Tcb.ServiceTable.dereference_as('_SERVICE_DESCRIPTOR_TABLE')
                    ssdts.add(ssdt_obj)
        else:
            print "[x64] Gathering all referenced SSDTs from KeAddSystemServiceTable..."
            # The NT module always loads first 
            ntos = list(modules.lsmod(addr_space))[0]
            func_rva = ntos.getprocaddress("KeAddSystemServiceTable")
            if func_rva == None:
                raise StopIteration("Cannot locate KeAddSystemServiceTable")
            KeAddSystemServiceTable = ntos.DllBase + func_rva
            for table_addr in find_tables(ntos.DllBase, KeAddSystemServiceTable, addr_space):
                ssdt_obj = obj.Object("_SERVICE_DESCRIPTOR_TABLE", table_addr, addr_space)
                ssdts.add(ssdt_obj)

        # Get a list of *unique* SSDT entries. Typically we see only two.
        tables = set()

        for ssdt_obj in ssdts:
            for i, desc in enumerate(ssdt_obj.Descriptors):
                # Apply some extra checks - KiServiceTable should reside in kernel memory and ServiceLimit 
                # should be greater than 0 but not unbelievably high
                if not desc.is_valid() or desc.ServiceLimit <= 0 or desc.ServiceLimit >= 2048 or desc.KiServiceTable <= 0x80000000:
                    break
                else:
                    tables.add((i, desc.KiServiceTable.v(), desc.ServiceLimit.v()))

        print "Finding appropriate address space for tables..."
        tables_with_vm = []
        procs = list(tasks.pslist(addr_space))
        for idx, table, n in tables:
            vm = tasks.find_space(addr_space, procs, table)
            if vm:
                tables_with_vm.append((idx, table, n, vm))
            else:
                debug.debug("[SSDT not resident at 0x{0:08X}]\n".format(table))

        for idx, table, n, vm in sorted(tables_with_vm, key = itemgetter(0)):
            yield idx, table, n, vm, mods, mod_addrs

    def unified_output(self, data):
        if not self._config.VERBOSE:
            return TreeGrid([("Table", str),
                       ("TableOffset", Address),
                       ("NumEntries", int),
                       ("Entry", Address),
                       ("Addr", Address),
                       ("Function", str),
                       ("Owner", str)],
                        self.generator(data))
        else:
            return TreeGrid([("Table", str),
                       ("TableOffset", Address),
                       ("NumEntries", int),
                       ("Entry", Address),
                       ("Addr", Address),
                       ("Function", str),
                       ("Owner", str),
                       ("Destination", Address),
                       ("HookName", str)],
                        self.generator(data))


    def generator(self, data):

        addr_space = utils.load_as(self._config)
        syscalls = addr_space.profile.syscalls
        bits32 = addr_space.profile.metadata.get('memory_model', '32bit') == '32bit'

        # Print out the entries for each table
        for idx, table, n, vm, mods, mod_addrs in data:
            table_name = "SSDT[{0}]".format(idx)
            table_offset = Address(table)
            num_entries = int(n)
            for i in range(n):
                if bits32:
                    # These are absolute function addresses in kernel memory. 
                    syscall_addr = obj.Object('address', table + (i * 4), vm).v()
                else:
                    # These must be signed long for x64 because they are RVAs relative
                    # to the base of the table and can be negative. 
                    offset = obj.Object('long', table + (i * 4), vm).v()
                    if offset == None:
                        continue

                    # The offset is the top 20 bits of the 32 bit number. 
                    syscall_addr = table + (offset >> 4)
                try:
                    syscall_name = syscalls[idx][i]
                except IndexError:
                    syscall_name = "UNKNOWN"

                syscall_mod = tasks.find_module(mods, mod_addrs, addr_space.address_mask(syscall_addr))
                if syscall_mod:
                    syscall_modname = syscall_mod.BaseDllName
                else:
                    syscall_modname = "UNKNOWN"

                if not self._config.VERBOSE:
                    yield (0, [table_name, table_offset, num_entries, Address(idx * 0x1000 + i), 
                            Address(syscall_addr), str(syscall_name), str(syscall_modname)])

                ## check for inline hooks if in --verbose mode, we're analyzing
                ## an x86 model system and the sycall_mod is available 
                if (self._config.VERBOSE and 
                            addr_space.profile.metadata.get('memory_model', '32bit') == '32bit' and 
                            syscall_mod is not None):

                        ## leverage this static method from apihooks
                        ret = apihooks.ApiHooks.check_inline(va = syscall_addr, addr_space = vm, 
                                                mem_start = syscall_mod.DllBase, 
                                                mem_end = syscall_mod.DllBase + syscall_mod.SizeOfImage)
                        ## could not analyze the memory
                        if ret == None:
                            yield (0, [table_name, table_offset, num_entries, Address(idx * 0x1000 + i), 
                                    Address(syscall_addr), str(syscall_name), str(syscall_modname), 
                                    Address(0), "NotInline"])
                            continue 
                        (hooked, data, dest_addr) = ret
                        ## the function isn't hooked
                        if not hooked:
                            yield (0, [table_name, table_offset, num_entries, Address(idx * 0x1000 + i), 
                                    Address(syscall_addr), str(syscall_name), str(syscall_modname), 
                                    Address(0), "NotInline"])
                            continue 
                        ## we found a hook, try to resolve the hooker. no mask required because
                        ## we currently only work on x86 anyway
                        hook_mod = tasks.find_module(mods, mod_addrs, dest_addr)
                        if hook_mod: 
                            hook_name = hook_mod.BaseDllName
                        else:
                            hook_name = "UNKNOWN"
                        ## report it now 
                        yield (0, [table_name, table_offset, num_entries, Address(idx * 0x1000 + i), 
                                Address(syscall_addr), str(syscall_name), str(syscall_modname),
                                Address(dest_addr), str(hook_name)])


    def render_text(self, outfd, data):
        addr_space = utils.load_as(self._config)
        syscalls = addr_space.profile.syscalls
        bits32 = addr_space.profile.metadata.get('memory_model', '32bit') == '32bit'

        # Print out the entries for each table
        for idx, table, n, vm, mods, mod_addrs in data:
            outfd.write("SSDT[{0}] at {1:x} with {2} entries\n".format(idx, table, n))
            for i in range(n):
                if bits32:
                    # These are absolute function addresses in kernel memory. 
                    syscall_addr = obj.Object('address', table + (i * 4), vm).v()
                else:
                    # These must be signed long for x64 because they are RVAs relative
                    # to the base of the table and can be negative. 
                    offset = obj.Object('long', table + (i * 4), vm).v()
                    if offset == None:
                        continue

                    # The offset is the top 20 bits of the 32 bit number. 
                    syscall_addr = table + (offset >> 4)
                try:
                    syscall_name = syscalls[idx][i]
                except IndexError:
                    syscall_name = "UNKNOWN"

                syscall_mod = tasks.find_module(mods, mod_addrs, addr_space.address_mask(syscall_addr))
                if syscall_mod:
                    syscall_modname = syscall_mod.BaseDllName
                else:
                    syscall_modname = "UNKNOWN"

                outfd.write("  Entry {0:#06x}: {1:#x} ({2}) owned by {3}\n".format(idx * 0x1000 + i,
                                                                   syscall_addr,
                                                                   syscall_name,
                                                                   syscall_modname))

                ## check for inline hooks if in --verbose mode, we're analyzing
                ## an x86 model system and the sycall_mod is available 
                if (self._config.VERBOSE and 
                            addr_space.profile.metadata.get('memory_model', '32bit') == '32bit' and 
                            syscall_mod is not None):

                        ## leverage this static method from apihooks
                        ret = apihooks.ApiHooks.check_inline(va = syscall_addr, addr_space = vm, 
                                                mem_start = syscall_mod.DllBase, 
                                                mem_end = syscall_mod.DllBase + syscall_mod.SizeOfImage)
                        ## could not analyze the memory
                        if ret == None:
                            continue 
                        (hooked, data, dest_addr) = ret
                        ## the function isn't hooked
                        if not hooked:
                            continue 
                        ## we found a hook, try to resolve the hooker. no mask required because
                        ## we currently only work on x86 anyway
                        hook_mod = tasks.find_module(mods, mod_addrs, dest_addr)
                        if hook_mod: 
                            hook_name = hook_mod.BaseDllName
                        else:
                            hook_name = "UNKNOWN"
                        ## report it now 
                        outfd.write("  ** INLINE HOOK? => {0:#x} ({1})\n".format(dest_addr, hook_name))
