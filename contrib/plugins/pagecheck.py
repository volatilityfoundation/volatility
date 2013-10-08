# Volatility
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

import volatility.commands as commands
import volatility.utils as utils

class PageCheck(commands.Command):
    """Reads the available pages and reports if any are inaccessible"""

    def render_text(self, outfd, data):
        """Displays any page errors"""
        found = False
        for page, vtop, size, pde, pte in data:
            found = True
            outfd.write("(V): 0x{0:08x} [PDE] 0x{3:08x} [PTE] 0x{4:08x} (P): 0x{1:08x} Size: 0x{2:08x}\n".format(page, vtop, size, pde, pte))
        if not found:
            outfd.write("No page failures found!")

    def calculate(self):
        """Calculate returns the results of the available pages validity"""
        addr_space = utils.load_as(self._config)
        for page, size in addr_space.get_available_pages():
            output = addr_space.read(page, size)
            if output == None:
                pde_value = addr_space.get_pde(page)
                pte_value = addr_space.get_pte(page, pde_value)
                yield page, addr_space.vtop(page), size, pde_value, pte_value
