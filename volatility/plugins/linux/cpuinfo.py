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

import volatility.plugins.linux.common as linux_common
import volatility.obj as obj

class linux_cpuinfo(linux_common.AbstractLinuxIntelCommand):
    """Prints info about each active processor"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        cpus = self.online_cpus()

        if len(cpus) > 1 and self.get_per_cpu_symbol("cpu_info"):
            func = self.get_info_smp

        elif self.get_per_cpu_symbol("boot_cpu_data"):
            func = self.get_info_single

        else:
            raise AttributeError, "Unable to get CPU info for memory capture"

        return func()

    def get_info_single(self):

        cpu = obj.Object("cpuinfo_x86", offset = self.addr_space.profile.get_symbol("boot_cpu_data"), vm = self.addr_space)

        yield 0, cpu

    def get_info_smp(self):
        """
        pulls the per_cpu cpu info
        will break apart the per_cpu code if a future plugin needs it
        """

        for i, cpu in self.walk_per_cpu_var("cpu_info", "cpuinfo_x86"):
            yield i, cpu
            
    def get_per_cpu_symbol(self, sym_name, module = "kernel"):
        """
        In 2.6.3x, Linux changed how the symbols for per_cpu variables were named
        This handles both formats so plugins needing per-cpu vars are cleaner
        """

        ret = self.addr_space.profile.get_symbol(sym_name, module = module)

        if not ret:
            ret = self.addr_space.profile.get_symbol("per_cpu__" + sym_name, module = module)

        return ret

    def online_cpus(self):
        """ returns a list of online cpus (the processor numbers) """
        cpu_online_bits_addr = self.addr_space.profile.get_symbol("cpu_online_bits")
        cpu_present_map_addr = self.addr_space.profile.get_symbol("cpu_present_map")

        #later kernels..
        if cpu_online_bits_addr:
            bmap = obj.Object("unsigned long", offset = cpu_online_bits_addr, vm = self.addr_space)

        elif cpu_present_map_addr:
            bmap = obj.Object("unsigned long", offset = cpu_present_map_addr, vm = self.addr_space)

        else:
            raise AttributeError, "Unable to determine number of online CPUs for memory capture"

        cpus = []
        for i in range(8):
            if bmap & (1 << i):
                cpus.append(i)

        return cpus

    def walk_per_cpu_var(self, per_var, var_type):

        cpus = self.online_cpus()

        # get the highest numbered cpu
        max_cpu = cpus[-1] + 1

        offset_var = self.addr_space.profile.get_symbol("__per_cpu_offset")
        per_offsets = obj.Object(theType = 'Array', targetType = 'unsigned long', count = max_cpu, offset = offset_var, vm = self.addr_space)

        for i in range(max_cpu):

            offset = per_offsets[i]

            cpu_var = self.get_per_cpu_symbol(per_var)

            addr = cpu_var + offset.v()
            var = obj.Object(var_type, offset = addr, vm = self.addr_space)

            yield i, var

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Processor", "12"),
                                  ("Vendor", "16"),
                                  ("Model", "")])
        for i, cpu in data:
            self.table_row(outfd, str(i), cpu.x86_vendor_id, cpu.x86_model_id)

