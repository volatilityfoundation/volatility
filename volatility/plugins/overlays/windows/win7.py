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
@author:       The Volatility Foundation
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net

This file provides support for Windows 7.
"""

#pylint: disable-msg=C0111

import windows
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611

class Win7Pointer64(obj.ProfileModification):
    before = ['WindowsOverlay', 'WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x >= 6,
                  'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        profile.native_types.update({'pointer64': [8, '<Q']})

class Win7KDBG(windows.AbstractKDBGMod):
    before = ['WindowsOverlay', 'VistaKDBG']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1}
    kdbgsize = 0x340

class Win7x86DTB(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'memory_model': lambda x: x == '32bit',
                  }

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                    'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x26\x00")]],
                                          }]}
        profile.merge_overlay(overlay)

class Win7x64DTB(obj.ProfileModification):
    before = ['WindowsOverlay', 'Windows64Overlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'memory_model': lambda x: x == '64bit',
                  }

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                    'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x58\x00")]],
                                          }]}
        profile.merge_overlay(overlay)

class _OBJECT_HEADER(windows._OBJECT_HEADER):
    """A Volatility object to handle Windows 7 object headers.

    Windows 7 changes the way objects are handled:
    References: http://www.codemachine.com/article_objectheader.html
    """

    type_map = { 2: 'Type',
                3: 'Directory',
                4: 'SymbolicLink',
                5: 'Token',
                6: 'Job',
                7: 'Process',
                8: 'Thread',
                9: 'UserApcReserve',
                10: 'IoCompletionReserve',
                11: 'DebugObject',
                12: 'Event',
                13: 'EventPair',
                14: 'Mutant',
                15: 'Callback',
                16: 'Semaphore',
                17: 'Timer',
                18: 'Profile',
                19: 'KeyedEvent',
                20: 'WindowStation',
                21: 'Desktop',
                22: 'TpWorkerFactory',
                23: 'Adapter',
                24: 'Controller',
                25: 'Device',
                26: 'Driver',
                27: 'IoCompletion',
                28: 'File',
                29: 'TmTm',
                30: 'TmTx',
                31: 'TmRm',
                32: 'TmEn',
                33: 'Section',
                34: 'Session',
                35: 'Key',
                36: 'ALPC Port',
                37: 'PowerRequest',
                38: 'WmiGuid',
                39: 'EtwRegistration',
                40: 'EtwConsumer',
                41: 'FilterConnectionPort',
                42: 'FilterCommunicationPort',
                43: 'PcwObject',
            }

    # This specifies the order the headers are found below the _OBJECT_HEADER
    optional_header_mask = (('CreatorInfo', '_OBJECT_HEADER_CREATOR_INFO', 0x01),
                            ('NameInfo', '_OBJECT_HEADER_NAME_INFO', 0x02),
                            ('HandleInfo', '_OBJECT_HEADER_HANDLE_INFO', 0x04),
                            ('QuotaInfo', '_OBJECT_HEADER_QUOTA_INFO', 0x08),
                            ('ProcessInfo', '_OBJECT_HEADER_PROCESS_INFO', 0x10))

    def find_optional_headers(self):
        """Find this object's optional headers."""
        offset = self.obj_offset
        info_mask = int(self.InfoMask)

        for name, struct, mask in self.optional_header_mask:
            if info_mask & mask:
                offset -= self.obj_vm.profile.get_obj_size(struct)
                o = obj.Object(struct, offset, self.obj_vm, native_vm = self.obj_native_vm)
            else:
                o = obj.NoneObject("Header {0} not set for object at {1:#x}".format(name, offset))

            self.newattr(name, o)

    def get_object_type(self):
        """Return the object's type as a string"""
        
        # wrap this in int() rather than calling .v() because the win10
        # property may return an int by default which doesn't have .v()
        return self.type_map.get(int(self.TypeIndex), '')

class Win7ObjectClasses(obj.ProfileModification):
    before = ['WindowsOverlay', 'WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 1}

    def modification(self, profile):
        profile.object_classes.update({'_OBJECT_HEADER': _OBJECT_HEADER})

class Win7x86Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x1)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0x1ff)]],
                                        }]}
        profile.merge_overlay(overlay)

class Win7x64Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x1)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0xff)]],
                                        }]}
        profile.merge_overlay(overlay)

class Win7SP0x86(obj.Profile):
    """ A Profile for Windows 7 SP0 x86 """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 1
    _md_build = 7600
    _md_vtype_module = 'volatility.plugins.overlays.windows.win7_sp0_x86_vtypes'
    _md_product = ["NtProductWinNt"]

class Win7SP1x86(obj.Profile):
    """ A Profile for Windows 7 SP1 x86 """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 1
    _md_build = 7601
    _md_vtype_module = 'volatility.plugins.overlays.windows.win7_sp1_x86_vtypes'
    _md_product = ["NtProductWinNt"]

class Win7SP1x86_23418(obj.Profile):
    """ A Profile for Windows 7 SP1 x86 (6.1.7601.23418 / 2016-04-09) """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 1
    _md_build = 7601
    _md_vtype_module = 'volatility.plugins.overlays.windows.win7_sp1_x86_BBA98F40_vtypes'
    _md_product = ["NtProductWinNt"]

class Win7SP0x64(obj.Profile):
    """ A Profile for Windows 7 SP0 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 1
    _md_build = 7600
    _md_vtype_module = 'volatility.plugins.overlays.windows.win7_sp0_x64_vtypes'
    _md_product = ["NtProductWinNt"]

class Win7SP1x64(obj.Profile):
    """ A Profile for Windows 7 SP1 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 1
    _md_build = 7601
    _md_vtype_module = 'volatility.plugins.overlays.windows.win7_sp1_x64_vtypes'
    _md_product = ["NtProductWinNt"]

class Win7SP1x64_23418(obj.Profile):
    """ A Profile for Windows 7 SP1 x64 (6.1.7601.23418 / 2016-04-09) """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 1
    _md_build = 7601
    _md_vtype_module = 'volatility.plugins.overlays.windows.win7_sp1_x64_632B36E0_vtypes'
    _md_product = ["NtProductWinNt"]

class Win2008R2SP0x64(Win7SP0x64):
    """ A Profile for Windows 2008 R2 SP0 x64 """
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win2008R2SP1x64(Win7SP1x64):
    """ A Profile for Windows 2008 R2 SP1 x64 """
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win2008R2SP1x64_23418(Win7SP1x64_23418):
    """ A Profile for Windows 2008 R2 SP1 x64 (6.1.7601.23418 / 2016-04-09) """
    _md_product = ["NtProductLanManNt", "NtProductServer"]
