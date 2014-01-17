# Volatility
# Copyright (c) 2011 Michael Cohen <scudette@gmail.com>
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
Support for 64 bit Linux systems.

@author:      Michael Cohen
@license:      GNU General Public License 2.0
@contact:      scudette@gmail.com
"""

from volatility import obj

class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def generate_suggestions(self):
        """Tries to locate the DTB."""
        profile = self.obj_vm.profile

        yield profile.get_symbol("init_level4_pgt") - 0xffffffff80000000

class Linux64ObjectClasses(obj.ProfileModification):
    """ Makes slight changes to the DTB checker """
    conditions = {'os': lambda x: x == 'linux',
                  'memory_model': lambda x: x == '64bit'}
    before = ['LinuxObjectClasses']
    def modification(self, profile):
        profile.object_classes.update({
            'VolatilityDTB': VolatilityDTB
                                       })
