# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
@author:       The Volatility Foundation 
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net

This file provides support for Windows Vista. 
"""

#pylint: disable-msg=C0111

import windows
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.obj as obj

class _ETHREAD(windows._ETHREAD):
    """A class for Windows 7 ETHREAD objects"""

    def owning_process(self):
        """Return the EPROCESS that owns this thread"""
        return self.Tcb.Process.dereference_as("_EPROCESS")

class _POOL_HEADER(windows._POOL_HEADER):
    """A class for pool headers"""

    @property
    def NonPagedPool(self):
        return self.PoolType.v() % 2 == 0 and self.PoolType.v() > 0

    @property
    def PagedPool(self):
        return self.PoolType.v() % 2 == 1

class _TOKEN(windows._TOKEN):

    def privileges(self):
        """Generator for privileges.

        @yields a tuple (value, present, enabled, default). 
        """
        for i in range(0, 64):
            bit_position = 1 << i
            present = self.Privileges.Present & bit_position != 0
            enabled = self.Privileges.Enabled & bit_position != 0
            default = self.Privileges.EnabledByDefault & bit_position != 0
            yield i, present, enabled, default

class VistaWin7KPCR(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os' : lambda x: x == 'windows',
                  'major': lambda x: x == 6}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                    'KPCR' : [ None, ['VolatilityKPCR', dict(configname = "KPCR")]],
                                          }]}
        profile.merge_overlay(overlay)

class Vistax86DTB(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'memory_model': lambda x: x == '32bit',
                  }

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                    'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x20\x00")]],
                                          }]}
        profile.merge_overlay(overlay)

class Vistax64DTB(obj.ProfileModification):
    before = ['WindowsOverlay', 'Windows64Overlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'memory_model': lambda x: x == '64bit',
                  }

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                    'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x30\x00")]],
                                          }]}
        profile.merge_overlay(overlay)


class VistaObjectClasses(obj.ProfileModification):
    before = ['WindowsOverlay', 'WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x >= 6,
                  }

    def modification(self, profile):
        profile.object_classes.update({'_ETHREAD'    : _ETHREAD, 
                                       '_POOL_HEADER': _POOL_HEADER, 
                                        '_TOKEN': _TOKEN})

class VistaKDBG(windows.AbstractKDBGMod):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0}
    kdbgsize = 0x328

class VistaSP1KDBG(windows.AbstractKDBGMod):
    before = ['WindowsOverlay', 'VistaKDBG']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x >= 6001,
                  }
    kdbgsize = 0x330

class VistaPolicyKey(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows',
                  'major': lambda x: x == 6}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'PolicyKey': [0x0, ['VolatilityMagic', dict(value = "PolEKList")]],
                                        }]}
        profile.merge_overlay(overlay)

class VistaSP0x86Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x == 6000}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x4)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0xff)]],
                                        }]}
        profile.merge_overlay(overlay)

class VistaSP1x86Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x == 6001}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x1)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0xff)]],
                                        }]}
        profile.merge_overlay(overlay)

class VistaSP2x86Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x == 6002}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x1)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0x1fe)]],
                                        }]}
        profile.merge_overlay(overlay)


class VistaSP0x64Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x == 6000}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x4)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0x7f)]],
                                        }]}
        profile.merge_overlay(overlay)


class VistaSP1x64Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x == 6001}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x1)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0x7f)]],
                                        }]}
        profile.merge_overlay(overlay)

class VistaSP2x64Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x == 6002}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x1)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0xfe)]],
                                        }]}
        profile.merge_overlay(overlay)

class VistaSP0x86(obj.Profile):
    """ A Profile for Windows Vista SP0 x86 """
    _md_major = 6
    _md_minor = 0
    _md_build = 6000
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_vtype_module = 'volatility.plugins.overlays.windows.vista_sp0_x86_vtypes'
    _md_product = ["NtProductWinNt"]

class VistaSP0x64(obj.Profile):
    """ A Profile for Windows Vista SP0 x64 """
    _md_major = 6
    _md_minor = 0
    _md_build = 6000
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_vtype_module = 'volatility.plugins.overlays.windows.vista_sp0_x64_vtypes'
    _md_product = ["NtProductWinNt"]

class VistaSP1x86(obj.Profile):
    """ A Profile for Windows Vista SP1 x86 """
    _md_major = 6
    _md_minor = 0
    _md_build = 6001
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_vtype_module = 'volatility.plugins.overlays.windows.vista_sp1_x86_vtypes'
    _md_product = ["NtProductWinNt"]

class VistaSP1x64(obj.Profile):
    """ A Profile for Windows Vista SP1 x64 """
    _md_major = 6
    _md_minor = 0
    _md_build = 6001
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_vtype_module = 'volatility.plugins.overlays.windows.vista_sp1_x64_vtypes'
    _md_product = ["NtProductWinNt"]

class VistaSP2x86(obj.Profile):
    """ A Profile for Windows Vista SP2 x86 """
    _md_major = 6
    _md_minor = 0
    _md_build = 6002
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_vtype_module = 'volatility.plugins.overlays.windows.vista_sp2_x86_vtypes'
    _md_product = ["NtProductWinNt"]

class VistaSP2x64(obj.Profile):
    """ A Profile for Windows Vista SP2 x64 """
    _md_major = 6
    _md_minor = 0
    _md_build = 6002
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_vtype_module = 'volatility.plugins.overlays.windows.vista_sp2_x64_vtypes'
    _md_product = ["NtProductWinNt"]

class Win2008SP1x64(VistaSP1x64):
    """ A Profile for Windows 2008 SP1 x64 """
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win2008SP2x64(VistaSP2x64):
    """ A Profile for Windows 2008 SP2 x64 """
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win2008SP1x86(VistaSP1x86):
    """ A Profile for Windows 2008 SP1 x86 """
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win2008SP2x86(VistaSP2x86):
    """ A Profile for Windows 2008 SP2 x86 """
    _md_product = ["NtProductLanManNt", "NtProductServer"]
