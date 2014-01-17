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
import volatility.plugins.mac.common as common

class mac_machine_info(common.AbstractMacCommand):
    """ Prints machine information about the sample """

    def calculate(self):
        common.set_plugin_members(self)

        machine_info = obj.Object("machine_info", offset = self.addr_space.profile.get_symbol("_machine_info"), vm = self.addr_space)

        yield machine_info
 
    def render_text(self, outfd, data):
        for machine_info in data:
            
            info = (("Major Version:", machine_info.major_version),
                    ("Minor Version:", machine_info.minor_version),
                    ("Memory Size:", machine_info.max_mem),
                    ("Max CPUs:",  machine_info.max_cpus),
                    ("Physical CPUs:", machine_info.physical_cpu),
                    ("Logical CPUs:", machine_info.logical_cpu),
                    )

            for i in info:
                outfd.write("{0:15} {1}\n".format(i[0], i[1]))
