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

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.obj as obj


class Win10SmGlobals(common.AbstractWindowsCommand):
    """Find the SmGlobals value for Windows 10"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    @staticmethod
    def register_options(config):
        config.add_option('SMGLOBALS', default = None, type = 'int',
                          help = ("Specify the virtual address of nt!SmGlobals"
                                  " (valid for Windows 10 only)"))

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

    def calculate(self):
        address_space = utils.load_as(self._config)

        return obj.VolMagic(address_space).SmGlobals.v()

    def render_text(self, outfd, data):
        if data:
            outfd.write("{0:#x}".format(data))
        else:
            outfd.write("Unable to find nt!SmGlobals")
