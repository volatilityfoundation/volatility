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
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.plugins.linux.common as linux_common
import volatility.obj as obj

class linux_cpuinfo(linux_common.AbstractLinuxCommand):
    """Prints info about each active processor"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        cpus = linux_common.online_cpus(self)

        if len(cpus) > 1 and self.get_per_cpu_symbol("cpu_info"):
            func = self.get_info_smp

        elif self.get_per_cpu_symbol("boot_cpu_data"):
            func = self.get_info_single

        else:
            raise AttributeError, "Unable to get CPU info for memory capture"

        return func()

    def get_info_single(self):

        cpu = obj.Object("cpuinfo_x86", offset = self.get_profile_symbol("boot_cpu_data"), vm = self.addr_space)

        yield 0, cpu

    # pulls the per_cpu cpu info
    # will break apart the per_cpu code if a future plugin needs it
    def get_info_smp(self):

        for i, cpu in linux_common.walk_per_cpu_var(self, "cpu_info", "cpuinfo_x86"):
            yield i, cpu

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Processor", "12"),
                                  ("Vendor", "16"),
                                  ("Model", "")])
        for i, cpu in data:
            self.table_row(outfd, str(i), cpu.x86_vendor_id, cpu.x86_model_id)

