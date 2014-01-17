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

import volatility.plugins.mac.common as common
import volatility.debug as debug

class mac_find_aslr_shift(common.AbstractMacCommand):
    """ Find the ASLR shift value for 10.8+ images """

    def calculate(self):
        common.set_plugin_members(self)

        yield self.profile.shift_address
 
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Shift Value", "#018x")])
        for shift_address in data:
            if shift_address == 0:
                debug.error("Shift addresses are only required on 10.8+ images")
            else:
                self.table_row(outfd, shift_address)
