# Volatility
# Copyright (C) 2009-2013 Volatility Foundation
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

import volatility.plugins.crashinfo as crashinfo
import volatility.plugins.linux.common as linux_common

class LiMEInfo(linux_common.AbstractLinuxCommand):
    """Dump Lime file format information"""
    
    target_as = ['LimeAddressSpace']
    
    def calculate(self):
        """Determines the address space"""
        linux_common.set_plugin_members(self)
        
        result = None
        adrs = self.addr_space
        while adrs:
            if adrs.__class__.__name__ in self.target_as:
                result = adrs
            adrs = adrs.base

        if result is None:
            debug.error("Memory Image could not be identified as {0}".format(self.target_as))

        return result

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Memory Start", "[addrpad]"), 
                                  ("Memory End", "[addrpad]"),
                                  ("Size", "[addrpad]")])
        
        for seg in data.runs:
            self.table_row(outfd, seg[0], seg[0] + seg[2] - 1, seg[2])
