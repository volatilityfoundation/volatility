# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2009 Timothy D. Morgan (strings optimization)
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

from bisect import bisect_right
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.strings as strings
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod as linux_lsmod

class linux_strings(strings.Strings, linux_common.AbstractLinuxCommand):
    """Match physical offsets to virtual addresses (may take a while, VERY verbose)"""

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'linux'

    def get_processes(self, addr_space):
        """Enumerate processes based on user options.

        :param      addr_space | <addrspace.AbstractVirtualAddressSpace>

        :returns    <list> 
        """
       
        tasks = linux_pslist.linux_pslist(self._config).calculate()

        try:
            if self._config.PID is not None:
                pidlist = [int(p) for p in self._config.PID.split(',')]
                tasks = [t for t in tasks if int(t.pid) in pidlist]
        except (ValueError, TypeError):
            debug.error("Invalid PID {0}".format(self._config.PID))

        return tasks

    @classmethod
    def get_modules(cls, addr_space):    
        """Enumerate the kernel modules. 

        :param      addr_space | <addrspace.AbstractVirtualAddressSpace>
        
        :returns    <tuple>
        """

        mask = addr_space.address_mask
        config = addr_space.get_config()
        modules = linux_lsmod.linux_lsmod(config).calculate()
        mods = dict((mask(mod[0].module_core), mod[0]) for mod in modules)
        mod_addrs = sorted(mods.keys())
         
        return (mods, mod_addrs)

    @classmethod
    def find_module(cls, modlist, mod_addrs, addr_space, vpage):
        """Determine which module owns a virtual page. 

        :param      modlist     | <list>
                    mod_addrs   | <list>
                    addr_space  | <addrspace.AbstractVirtualAddressSpace>
                    vpage       | <int> 
        
        :returns    <module> || None
        """

        pos = bisect_right(mod_addrs, vpage) - 1
        if pos == -1:
            return None
        mod = modlist[mod_addrs[pos]]

        compare = mod.obj_vm.address_compare
        if (compare(vpage, mod.module_core) != -1 and
                compare(vpage, mod.module_core + mod.core_size) == -1):
            return mod
        else:
            return None

    @classmethod
    def get_module_name(cls, module):
        """Get the name of a kernel module.

        :param      module      | <module>
        
        :returns    <str>
        """

        return str(module.m("name"))

    @classmethod
    def get_task_pid(cls, task):
        """Get the PID of a process. 

        :param      task   | <task>
        
        :returns    <int>
        """
        return task.pid
 
