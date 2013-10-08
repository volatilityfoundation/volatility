# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

#pylint: disable-msg=C0111

import volatility.plugins.common as common
import volatility.win32.network as network
import volatility.cache as cache
import volatility.utils as utils
import volatility.debug as debug

class Connections(common.AbstractWindowsCommand):
    """
    Print list of open connections [Windows XP and 2003 Only]
    ---------------------------------------------

    This module follows the handle table in tcpip.sys and prints
    current connections.

    Note that if you are using a hibernated image this might not work
    because Windows closes all connections before hibernating. You might
    find it more effective to do connscan instead.
    """
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("PHYSICAL-OFFSET", short_option = 'P', default = False,
                          cache_invalidator = False,
                          help = "Physical Offset", action = "store_true")

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 5)

    def render_text(self, outfd, data):
        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
        self.table_header(outfd,
                          [("Offset{0}".format(offsettype), "[addrpad]"),
                           ("Local Address", "25"),
                           ("Remote Address", "25"),
                           ("Pid", "")
                           ])

        for conn in data:
            if not self._config.PHYSICAL_OFFSET:
                offset = conn.obj_offset
            else:
                offset = conn.obj_vm.vtop(conn.obj_offset)
            local = "{0}:{1}".format(conn.LocalIpAddress, conn.LocalPort)
            remote = "{0}:{1}".format(conn.RemoteIpAddress, conn.RemotePort)
            self.table_row(outfd, offset, local, remote, conn.Pid)

    @cache.CacheDecorator("tests/connections")
    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")

        return network.determine_connections(addr_space)
