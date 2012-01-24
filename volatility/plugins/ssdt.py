# Volatility
# Copyright (C) 2008 Volatile Systems
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
#

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

from operator import itemgetter
from bisect import bisect_right

import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.commands as commands
import volatility.utils as utils
import volatility.debug as debug #pylint: disable-msg=W0611
from volatility.cache import CacheDecorator

#pylint: disable-msg=C0111

def find_module(modlist, mod_addrs, addr):
    """Uses binary search to find what module a given address resides in.

    This is much faster than a series of linear checks if you have
    to do it many times. Note that modlist and mod_addrs must be sorted
    in order of the module base address."""

    pos = bisect_right(mod_addrs, addr) - 1
    if pos == -1:
        return None
    mod = modlist[mod_addrs[pos]]

    if (addr >= mod.DllBase.v() and
        addr < mod.DllBase.v() + mod.SizeOfImage.v()):
        return mod
    else:
        return None

class SSDT(commands.command):
    "Display SSDT entries"
    # Declare meta information associated with this plugin
    meta_info = {
        'author': 'Brendan Dolan-Gavitt',
        'copyright': 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        'contact': 'bdolangavitt@wesleyan.edu',
        'license': 'GNU General Public License 2.0 or later',
        'url': 'http://moyix.blogspot.com/',
        'os': 'WIN_32_XP_SP2',
        'version': '1.0'}

    @CacheDecorator("tests/ssdt")
    def calculate(self):
        addr_space = utils.load_as(self._config)

        if addr_space.profile.metadata.get('memory_model', '') != '32bit':
            raise StopIteration

        ## Get a sorted list of module addresses
        mods = dict((mod.DllBase.v(), mod) for mod in modules.lsmod(addr_space))
        mod_addrs = sorted(mods.keys())

        # Gather up all SSDTs referenced by threads
        print "Gathering all referenced SSDTs from KTHREADs..."
        ssdts = set()
        for proc in tasks.pslist(addr_space):
            for thread in proc.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
                ssdt_obj = thread.Tcb.ServiceTable.dereference_as('_SERVICE_DESCRIPTOR_TABLE')
                ssdts.add(ssdt_obj)

        # Get a list of *unique* SSDT entries. Typically we see only two.
        tables = set()

        for ssdt_obj in ssdts:
            for i, desc in enumerate(ssdt_obj.Descriptors):
                # Apply some extra checks - KiServiceTable should reside in kernel memory and ServiceLimit 
                # should be greater than 0 but not unbelievably high
                if desc.is_valid() and desc.ServiceLimit > 0 and desc.ServiceLimit < 0xFFFF and desc.KiServiceTable > 0x80000000:
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

    def render_text(self, outfd, data):

        addr_space = utils.load_as(self._config)

        if addr_space.profile.metadata.get('memory_model', '') != '32bit':
            outfd.write("The SSDT plugin only supports 32bit systems\n  Please see issue 82 at volatility.googlecode.com for more details\n")
            return

        syscalls = addr_space.profile.syscalls

        # Print out the entries for each table
        for idx, table, n, vm, mods, mod_addrs in data:
            outfd.write("SSDT[{0}] at {1:x} with {2} entries\n".format(idx, table, n))
            if vm.is_valid_address(table):
                for i in range(n):
                    syscall_addr = obj.Object('unsigned long', table + (i * 4), vm).v()
                    try:
                        syscall_name = syscalls[idx][i]
                    except IndexError:
                        syscall_name = "UNKNOWN"

                    syscall_mod = find_module(mods, mod_addrs, syscall_addr)
                    if syscall_mod:
                        syscall_modname = syscall_mod.BaseDllName
                    else:
                        syscall_modname = "UNKNOWN"

                    outfd.write("  Entry {0:#06x}: {1:#x} ({2}) owned by {3}\n".format(idx * 0x1000 + i,
                                                                       syscall_addr,
                                                                       syscall_name,
                                                                       syscall_modname))
            else:
                outfd.write("  [SSDT not resident at 0x{0:08X} ]\n".format(table))
