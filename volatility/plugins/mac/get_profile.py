# Volatility
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
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.registry as registry
import volatility.plugins.mac.common as common

# based on kdbgscan
class mac_get_profile(common.AbstractMacCommand):

    def calculate(self):
        profilelist = [ p.__name__ for p in registry.get_plugin_classes(obj.Profile).values() ]
            

        for p in profilelist:
            self._config.update('PROFILE', p)
           
            buf = addrspace.BufferAddressSpace(self._config)
            if buf.profile.metadata.get('os', 'unknown') != 'mac':
                continue
        
            aspace = utils.load_as(self._config, astype = 'any')

            ver_addr = buf.profile.get_symbol("_version") 

            ver_buf = aspace.read(ver_addr, 32)

            if ver_buf and ver_buf.startswith("Darwin Kernel"):
                yield p, buf.profile.shift_address

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Profile", "50"), ("Shift Address", "[addrpad]")])

        for profile, shift_address in data:
            self.table_row(outfd, profile, shift_address)








