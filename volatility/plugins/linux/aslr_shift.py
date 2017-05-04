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

import volatility.utils as utils
import volatility.plugins.linux.common as common

class linux_aslr_shift(common.AbstractLinuxCommand):
    """Automatically detect the Linux ASLR shift"""

    def calculate(self):
        aspace = utils.load_as(self._config)
        
        yield aspace.profile.virtual_shift, aspace.profile.physical_shift

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Virtual Shift Address", "[addrpad]"), ("Physical Shift Address", "[addrpad]")])

        for v, p in data:
            self.table_row(outfd, v, p)


