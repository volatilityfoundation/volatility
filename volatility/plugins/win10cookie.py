# Volatility
# Copyright (C) 2007-2015 Volatility Foundation
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

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.obj as obj 

class Win10Cookie(common.AbstractWindowsCommand):
    """Find the ObHeaderCookie value for Windows 10"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    @staticmethod
    def register_options(config):
        config.add_option('COOKIE', default = None, type = 'int',
                          help = "Specify the address of nt!ObHeaderCookie (valid for Windows 10 only)")

    @staticmethod
    def is_valid_profile(profile):

        meta = profile.metadata 
        vers = (meta.get("major", 0), meta.get("minor", 0))

        # this algorithm only applies to Windows 10 or greater 
        return meta.get('os', '') == 'windows' and vers >= (6, 4)

    def calculate(self):
        address_space = utils.load_as(self._config)
        cookie = obj.VolMagic(address_space).ObHeaderCookie.v()
        yield cookie

    def render_text(self, outfd, data):
        for cookie in data:
            print cookie