# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

#pylint: disable-msg=C0111
from volatility import renderers

import volatility.plugins.common as common
import volatility.debug as debug
from volatility.renderers.basic import Address
import volatility.win32 as win32
import volatility.utils as utils
import volatility.protos as protos

class Sockets(common.AbstractWindowsCommand):
    """Print list of open sockets"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("PHYSICAL-OFFSET", short_option = 'P', default = False,
                          cache_invalidator = False,
                          help = "Physical Offset", action = "store_true")

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 5)

    text_sort_column = "port"

    def unified_output(self, data):
        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
        return renderers.TreeGrid(
                          [("Offset{0}".format(offsettype), Address),
                           ("PID", int),
                           ("Port", int),
                           ("Proto", int),
                           ("Protocol", str),
                           ("Address", str),
                           ("Create Time", str)
                           ], self.generator(data))

    def generator(self, data):
        for sock in data:
            if not self._config.PHYSICAL_OFFSET:
                offset = sock.obj_offset
            else:
                offset = sock.obj_vm.vtop(sock.obj_offset)

            yield (0, [Address(offset),
                             int(sock.Pid),
                             int(sock.LocalPort),
                             int(sock.Protocol),
                             str(protos.protos.get(sock.Protocol.v(), "-")),
                             str(sock.LocalIpAddress),
                             str(sock.CreateTime)])

    def render_text(self, outfd, data):
        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
        self.table_header(outfd,
                          [("Offset{0}".format(offsettype), "[addrpad]"),
                           ("PID", ">8"),
                           ("Port", ">6"),
                           ("Proto", ">6"),
                           ("Protocol", "15"),
                           ("Address", "15"),
                           ("Create Time", "")
                           ])

        for sock in data:
            if not self._config.PHYSICAL_OFFSET:
                offset = sock.obj_offset
            else:
                offset = sock.obj_vm.vtop(sock.obj_offset)

            self.table_row(outfd, offset, sock.Pid, sock.LocalPort, sock.Protocol,
                           protos.protos.get(sock.Protocol.v(), "-"),
                           sock.LocalIpAddress, sock.CreateTime)

    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")

        return win32.network.determine_sockets(addr_space)
