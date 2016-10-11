# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
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
@author:       Jamie Levy (Gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie@memoryanalysis.net

This file provides support for Windows 2003.
"""

#pylint: disable-msg=C0111

import volatility.plugins.overlays.windows.windows as windows
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.obj as obj

class Win2003x86Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x2)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0xff)]],
                                        }]}
        profile.merge_overlay(overlay)

class Win2003x64Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x2)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0x7f)]],
                                        }]}
        profile.merge_overlay(overlay)

class Win2003KDBG(windows.AbstractKDBGMod):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x >= 2}
    kdbgsize = 0x318

class Win2003SP0x86DTB(obj.ProfileModification):
    # Make sure we apply after the normal Win2003 DTB
    before = ['WindowsOverlay', 'Win2003x86DTB']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2,
                  'build': lambda x: x == 3789}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'DTBSignature': [ None, ['VolatilityMagic', dict(value = "\x03\x00\x1b\x00")]]}
                                        ]}
        profile.merge_overlay(overlay)

class Win2003x86DTB(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'DTBSignature': [ None, ['VolatilityMagic', dict(value = "\x03\x00\x1e\x00")]]}
                                        ]}
        profile.merge_overlay(overlay)

class Win2003x64DTB(obj.ProfileModification):
    before = ['WindowsOverlay', 'Windows64Overlay']
    conditions = {'os': lambda x : x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'KPCR' : [ None, ['VolatilityKPCR', dict(configname = "KPCR")]],
                        'DTBSignature': [ None, ['VolatilityMagic', dict(value = "\x03\x00\x2e\x00")]]}
                                        ]}
        profile.merge_overlay(overlay)

class EThreadCreateTime(obj.ProfileModification):
    before = ['WindowsOverlay']

    def check(self, profile):
        m = profile.metadata
        return (m.get('os', None) == 'windows' and
                ((m.get('major', 0) == 5 and m.get('minor', 0) >= 2) or
                 m.get('major', 0) >= 6) and
                 profile.__class__.__name__ != 'Win2003SP0x86')

    def modification(self, profile):
        overlay = {'_ETHREAD': [ None, {
                        'CreateTime' : [ None, ['WinTimeStamp', {}]]}
                                ]}
        profile.merge_overlay(overlay)

class Win2003SP0x86(obj.Profile):
    """ A Profile for Windows 2003 SP0 x86 """
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    # FIXME: 2003's build numbers didn't differentiate between SP0 and SP1/2
    # despite there being a large change. As such we fake a special build number
    # for 2003 SP0 to help us differentiate it
    _md_build = 3789
    _md_memory_model = '32bit'
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp0_x86_vtypes'
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win2003SP1x86(obj.Profile):
    """ A Profile for Windows 2003 SP1 x86 """
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    _md_build = 3790
    _md_memory_model = '32bit'
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp1_x86_vtypes'
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win2003SP2x86(obj.Profile):
    """ A Profile for Windows 2003 SP2 x86 """
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    # This is a fake build number. See the comment in Win2003SP0x86
    _md_build = 3791 
    _md_memory_model = '32bit'
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp2_x86_vtypes'
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win2003SP1x64(obj.Profile):
    """ A Profile for Windows 2003 SP1 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    _md_build = 3790
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp1_x64_vtypes'
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win2003SP2x64(obj.Profile):
    """ A Profile for Windows 2003 SP2 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    # This is a fake build number. See the comment in Win2003SP0x86
    _md_build = 3791
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp2_x64_vtypes'
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class WinXPSP1x64(Win2003SP1x64):
    """ A Profile for Windows XP SP1 x64 """
    _md_product = ["NtProductWinNt"]

class WinXPSP2x64(Win2003SP2x64):
    """ A Profile for Windows XP SP2 x64 """
    _md_product = ["NtProductWinNt"]

