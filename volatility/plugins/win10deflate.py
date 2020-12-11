# Copyright (C) 2019 FireEye, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Authors:
# Blaine Stancill <blaine.stancill@FireEye.com>
#
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement

import volatility.debug as debug
import volatility.plugins.common as common
import volatility.win32 as win32
import volatility.utils as utils
import volatility.obj as obj

from volatility.plugins.addrspaces.win10_memcompression import \
    Win10CompressedPagedMemory

PAGE_SIZE = 0x1000


def to_hexdump(base_address, data):
    hexdump = []
    for o, h, c in utils.Hexdump(data):
        hexdump.append(
            "{0:#010x}  {1:<48}  {2}".format(base_address + o, h, ''.join(c)))
    return "{0}\n".format("\n".join(hexdump))


class Win10Deflate(common.AbstractWindowsCommand):
    """Windows 10 page decompression plugin, decompresses a single page"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'PID of process', action = 'store',
                          type = 'int')
        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = ('EPROCESS offset (in hex) in'
                                  ' kernel address space'),
                          action = 'store', type = 'int')
        config.add_option('VA', default = None,
                          help = 'VA of page to decompress',
                          action = 'store', type = 'int')

    @staticmethod
    def register_options(config):
        config.add_option('VSPAGEFILENUMBER', default = 2,
                          help = ('Specify the page file number corresponding'
                                  ' to the Virtual Store (default is 2)'
                                  ' (valid for Windows 10 only)'),
                          action = 'store',
                          type = 'int')
        config.add_option('DISABLEWIN10MEMCOMPRESS', default = False,
                          help = ('Disables Win10 memory decompression address'
                                  ' spaces (valid for Windows 10 only)'),
                          action = 'store_true')

    @staticmethod
    def is_valid_profile(profile):
        os = profile.metadata.get('os', '')
        major = profile.metadata.get('major', 0)
        minor = profile.metadata.get('minor', 0)
        build = profile.metadata.get('build', 0)
        return (major >= 6
                and minor >= 4
                and os == 'windows'
                and build in [14393, 15063, 16299, 17134, 17763, 18362])

    def valid_arguments(self):
        if not (self._config.OFFSET or self._config.PID):
            debug.warning(
                "Provide either an EPROCESS offset or PID as the argument")
            return False

        if self._config.OFFSET and self._config.PID:
            debug.warning(
                "Provide an EPROCESS offset or PID as the argument, not both")
            return False

        if not self._config.VA:
            debug.warning("Provide a Virtual Address to decompress")
            return False

        return True

    def calculate(self):
        if not self.valid_arguments():
            return None

        address_space = utils.load_as(self._config)
        if not isinstance(address_space, Win10CompressedPagedMemory):
            debug.warning(
                "Address space not compatible with Win10 memory compression")
            return None

        # Get _EPROCESS for the supplied PID
        offset = self._config.OFFSET
        if self._config.PID:
            for p in win32.tasks.pslist(address_space):
                if p.UniqueProcessId.v() == self._config.PID:
                    offset = p.v()
                    break

        if not offset:
            debug.warning("Could not find the specified process")
            return None

        proc = obj.Object("_EPROCESS", offset = offset, vm = address_space)

        proc_address_space = proc.get_process_address_space()
        if not isinstance(proc_address_space, Win10CompressedPagedMemory):
            debug.warning(
                "Address space not compatible with Win10 memory compression")
            return None

        data = proc_address_space.read(self._config.VA, PAGE_SIZE)
        return data

    def render_text(self, outfd, data):
        if data:
            outfd.write(to_hexdump(self._config.VA, data))
        else:
            outfd.write("Failed to retrieve and decompress data")
