# Volatility
# Copyright (c) 2008-2014 Volatility Foundation
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

"""
@author:       The Volatility Foundation
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net

This file provides support for Windows 10.
"""

import volatility.plugins.overlays.windows.windows as windows
import volatility.obj as obj

class Win10x64DTB(obj.ProfileModification):
    """The Windows 10 64-bit DTB signature"""

    before = ['WindowsOverlay', 'Windows64Overlay', 'Win8x64DTB']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'memory_model': lambda x: x == '64bit',
                  }

    def modification(self, profile):
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\xb6\x00")]],
            }]})

class Win10x86DTB(obj.ProfileModification):
    """The Windows 10 32-bit DTB signature"""

    before = ['WindowsOverlay', 'Win8x86DTB']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'memory_model': lambda x: x == '32bit',
                  }

    def modification(self, profile):
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x2A\x00")]],
            }]})

class Win10x64(obj.Profile):
    """ A Profile for Windows 10 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 9841
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_vtypes'

class Win10x86(obj.Profile):
    """ A Profile for Windows 10 x86 """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 9841
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x86_vtypes'
