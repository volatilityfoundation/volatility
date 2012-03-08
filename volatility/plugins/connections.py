# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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
#

#pylint: disable-msg=C0111

import volatility.commands as commands
import volatility.win32.network as network
import volatility.cache as cache
import volatility.utils as utils

class Connections(commands.Command):
    """
    Print list of open connections [Windows XP Only]
    ---------------------------------------------

    This module follows the handle table of each task and prints
    current connections.

    Note that if you are using a hibernated image this might not work
    because Windows closes all sockets before hibernating. You might
    find it more effective to do conscan instead.
    """
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option("PHYSICAL-OFFSET", short_option = 'P', default = False,
                          cache_invalidator = False,
                          help = "Physical Offset", action = "store_true")

    def render_text(self, outfd, data):
        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
        outfd.write(" Offset{0}  Local Address             Remote Address            Pid   \n".format(offsettype) +
                    "---------- ------------------------- ------------------------- ------ \n")

        for conn in data:
            if not self._config.PHYSICAL_OFFSET:
                offset = conn.obj_offset
            else:
                offset = conn.obj_vm.vtop(conn.obj_offset)
            local = "{0}:{1}".format(conn.LocalIpAddress, conn.LocalPort)
            remote = "{0}:{1}".format(conn.RemoteIpAddress, conn.RemotePort)
            outfd.write("{0:#010x} {1:25} {2:25} {3:6}\n".format(offset, local, remote, conn.Pid))


    @cache.CacheDecorator("tests/connections")
    def calculate(self):
        addr_space = utils.load_as(self._config)

        return network.determine_connections(addr_space)
