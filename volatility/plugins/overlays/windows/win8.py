# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
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

This file provides support for Windows 8.
"""

import struct
import volatility.plugins.overlays.windows.windows as windows
import volatility.obj as obj
import volatility.constants as constants
import volatility.utils as utils
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.addrspace as addrspace
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.overlays.windows.pe_vtypes as pe_vtypes
import volatility.plugins.overlays.windows.ssdt_vtypes as ssdt_vtypes
import volatility.plugins.overlays.windows.win7 as win7
import volatility.plugins.overlays.windows.vista as vista

try:
    import distorm3
    has_distorm = True
except:
    has_distorm = False

class _HANDLE_TABLE32(windows._HANDLE_TABLE):
    """A class for 32-bit Windows 8 handle tables"""    

    @property
    def HandleCount(self):
        """The Windows 8 / 2012 handle table does not have a 
        HandleCount member, so we fake it. 

        Alternately, we could return len(self.handles()) and
        show a valid number in pslist, however pslist would 
        be much slower than normal.
        """

        return 0

    def get_item(self, entry, handle_value = 0):
        """Returns the OBJECT_HEADER of the associated handle. 
        The parent is the _HANDLE_TABLE_ENTRY so that an object
        can be linked to its GrantedAccess.
        """

        if entry.InfoTable == 0:
            return obj.NoneObject("LeafHandleValue pointer is invalid")

        return obj.Object("_OBJECT_HEADER", 
                          offset = entry.InfoTable & ~7, 
                          vm = self.obj_vm, 
                          parent = entry, 
                          handle_value = handle_value)

class _HANDLE_TABLE64(_HANDLE_TABLE32):
    """A class for 64-bit Windows 8 / 2012 handle tables"""   

    DECODE_MAGIC = 0x13

    def decode_pointer(self, value):
        """Decode a pointer like SAR. Since Python does not 
        have an operator for shift arithmetic, we implement
        one ourselves.
        """

        value = value & 0xFFFFFFFFFFFFFFF8
        value = value >> self.DECODE_MAGIC
        if (value & 1 << 44):
            return value | 0xFFFFF00000000000
        else:
            return value | 0xFFFF000000000000

    def get_item(self, entry, handle_value = 0):
        """Returns the OBJECT_HEADER of the associated handle. 
        The parent is the _HANDLE_TABLE_ENTRY so that an object
        can be linked to its GrantedAccess.
        """

        if entry.LowValue == 0:
            return obj.NoneObject("LowValue pointer is invalid")

        return obj.Object("_OBJECT_HEADER", 
                          offset = self.decode_pointer(entry.LowValue), 
                          vm = self.obj_vm, 
                          parent = entry, 
                          handle_value = handle_value)

class _HANDLE_TABLE_81R264(_HANDLE_TABLE64):
    """A class for 64-bit Windows 8.1 / 2012 R2 handle tables"""   
    DECODE_MAGIC = 0x10

class _PSP_CID_TABLE32(_HANDLE_TABLE32):
    """PspCidTable for 32-bit Windows 8"""

class _PSP_CID_TABLE64(_HANDLE_TABLE64):
    """PspCidTable for 64-bit Windows 8 and Server 2012"""

    def get_item(self, entry, handle_value = 0):
        """Starting with 8/2012 x64 the PsPCidTable pointers
        go directly to an object rather than an object header.
        """

        if entry.LowValue == 0:
            return obj.NoneObject("LowValue pointer is invalid")

        body_offset = self.obj_vm.profile.get_obj_offset("_OBJECT_HEADER", "Body")
        head_offset = self.decode_pointer(entry.LowValue) - body_offset

        return obj.Object("_OBJECT_HEADER", 
                          offset = head_offset, 
                          vm = self.obj_vm, 
                          parent = entry, 
                          handle_value = handle_value)

class _PSP_CID_TABLE_81R264(_PSP_CID_TABLE64):
    """PspCidTable for 64-bit Windows 8.1 and Server 2012 R2"""
    DECODE_MAGIC = 0x10

class _LDR_DATA_TABLE_ENTRY(pe_vtypes._LDR_DATA_TABLE_ENTRY):
    """A class for DLL modules"""
    
    @property
    def LoadCount(self):
        """The Windows 8 / 2012 module does not have a 
        LoadCount member, so we fake it.
        """

        return 0

class _OBJECT_HEADER(win7._OBJECT_HEADER):
    """A class for object headers on Win 8 / Server 2012"""

    # This specifies the order the headers are found below the _OBJECT_HEADER
    # Note the AuditInfo field which is new as of Windows 8 / 2012
    optional_header_mask = (('CreatorInfo', '_OBJECT_HEADER_CREATOR_INFO', 0x01),
                            ('NameInfo', '_OBJECT_HEADER_NAME_INFO', 0x02),
                            ('HandleInfo', '_OBJECT_HEADER_HANDLE_INFO', 0x04),
                            ('QuotaInfo', '_OBJECT_HEADER_QUOTA_INFO', 0x08),
                            ('ProcessInfo', '_OBJECT_HEADER_PROCESS_INFO', 0x10),
                            ('AuditInfo', '_OBJECT_HEADER_AUDIT_INFO', 0x40),
                            )

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
                18: 'IRTimer',
                19: 'Profile',
                20: 'KeyedEvent',
                21: 'WindowStation',
                22: 'Desktop',
                24: 'TpWorkerFactory',
                25: 'Adapter',
                26: 'Controller',
                27: 'Device',
                28: 'Driver',
                29: 'IoCompletion',
                30: 'WaitCompletionPacket',
                31: 'File',
                32: 'TmTm',
                33: 'TmTx',
                34: 'TmRm',
                35: 'TmEn',
                36: 'Section',
                37: 'Session',
                38: 'Key',
                39: 'ALPC Port',
                40: 'PowerRequest',
                41: 'WmiGuid',
                42: 'EtwRegistration',
                43: 'EtwConsumer',
                44: 'FilterConnectionPort',
                45: 'FilterCommunicationPort',
                46: 'PcwObject',
                47: 'DxgkSharedResource', 
                48: 'DxgkSharedSyncObject',
            }

    @property
    def GrantedAccess(self):
        """Return the object's granted access permissions"""

        if self.obj_parent:
            return self.obj_parent.GrantedAccessBits
        return obj.NoneObject("No parent known")


    def is_valid(self):
        """Determine if a given object header is valid"""

        if not obj.CType.is_valid(self):
            return False

        if self.InfoMask > 0x48:
            return False

        if self.PointerCount > 0x1000000 or self.PointerCount < 0:
            return False

        return True

class _OBJECT_HEADER_81R2(_OBJECT_HEADER):
    """A class for object headers on Win 8.1 / Server 2012 R2"""

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
                13: 'Mutant',
                14: 'Callback',
                15: 'Semaphore',
                16: 'Timer',
                17: 'IRTimer',
                18: 'Profile',
                19: 'KeyedEvent',
                20: 'WindowStation',
                21: 'Desktop',
                22: 'Composition',
                23: 'TpWorkerFactory',
                24: 'Adapter',
                25: 'Controller',
                26: 'Device',
                27: 'Driver',
                28: 'IoCompletion',
                29: 'WaitCompletionPacket',
                30: 'File',
                31: 'TmTm',
                32: 'TmTx',
                33: 'TmRm',
                34: 'TmEn',
                35: 'Section',
                36: 'Session',
                37: 'Key',
                38: 'ALPC Port',
                39: 'PowerRequest',
                40: 'WmiGuid',
                41: 'EtwRegistration',
                42: 'EtwConsumer',
                43: 'FilterConnectionPort',
                44: 'FilterCommunicationPort',
                45: 'PcwObject',
                46: 'DxgkSharedResource',
            }

class Win8KDBG(windows.AbstractKDBGMod):
    """The Windows 8 / 2012 KDBG signatures"""

    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 2}

    kdbgsize = 0x360

    def modification(self, profile):

        if profile.metadata.get('memory_model', '32bit') == '32bit':
            signature = '\x00\x00\x00\x00\x00\x00\x00\x00'
        else:
            signature = '\x03\xf8\xff\xff'
        signature += 'KDBG' + struct.pack('<H', self.kdbgsize)

        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'KDBGHeader': [ None, ['VolatilityMagic', dict(value = signature)]]
            }]})

class Win8x86DTB(obj.ProfileModification):
    """The Windows 8 32-bit DTB signature"""

    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 2,
                  'memory_model': lambda x: x == '32bit',
                  }

    def modification(self, profile):
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x28\x00")]],
            }]})

class Win8x64MaxCommit(obj.ProfileModification):
    """The Windows 8 / Server 2012 MM_MAX_COMMIT value"""

    before = ["Windows64Overlay"]
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 2,
                  'memory_model': lambda x: x == '64bit',
                  }

    def modification(self, profile):
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ 0x0, {
            'MM_MAX_COMMIT': [ 0x0, ['VolatilityMagic', dict(value = 0x7fffffff)]],
             }]})

class Win8x64DTB(obj.ProfileModification):
    """The Windows 8 32-bit DTB signature"""

    before = ['WindowsOverlay', 'Windows64Overlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 2,
                  'memory_model': lambda x: x == '64bit',
                  }

    def modification(self, profile):
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\xb2\x00")]],
            }]})

class Win8x86SyscallVTypes(obj.ProfileModification):
    """Applying the SSDT structures for Win 8 32-bit"""

    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 2}

    def modification(self, profile):
        # Same as 2003, which basically just means there are
        # only two SSDT tables by default. 
        profile.vtypes.update(ssdt_vtypes.ssdt_vtypes_2003)

class Win8ObjectClasses(obj.ProfileModification):
    before = ["WindowsObjectClasses", "Win7ObjectClasses", "WinPEObjectClasses", "MalwarePspCid"]
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 2}

    def modification(self, profile):

        memory_model = profile.metadata.get("memory_model", "32bit") 
        major = profile.metadata.get("major", 0)
        minor = profile.metadata.get("minor", 0)

        if memory_model == '32bit':
            handletable = _HANDLE_TABLE32
            pspcidtable = _PSP_CID_TABLE32
        else:
            if (major, minor) == (6, 3):
                handletable = _HANDLE_TABLE_81R264
                pspcidtable = _PSP_CID_TABLE_81R264
            else:
                handletable = _HANDLE_TABLE64
                pspcidtable = _PSP_CID_TABLE64

        if (major, minor) == (6, 3):
            objheader = _OBJECT_HEADER_81R2
        else:
            objheader = _OBJECT_HEADER

        profile.object_classes.update({
                "_LDR_DATA_TABLE_ENTRY": _LDR_DATA_TABLE_ENTRY, 
                "_HANDLE_TABLE": handletable,
                "_OBJECT_HEADER": objheader,
                "_PSP_CID_TABLE": pspcidtable,
                })

class Win8SP0x64(obj.Profile):
    """ A Profile for Windows 8 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 2
    _md_build = 9200
    _md_vtype_module = 'volatility.plugins.overlays.windows.win8_sp0_x64_vtypes'

class Win8SP1x64(obj.Profile):
    """ A Profile for Windows 8.1 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 3
    _md_build = 9600
    _md_vtype_module = 'volatility.plugins.overlays.windows.win8_sp1_x64_vtypes'

class Win2012x64(Win8SP0x64):
    """ A Profile for Windows Server 2012 x64 """
    _md_build = 9201 ##FIXME: fake build number to indicate server 2012 vs windows 8

class Win2012R2x64(Win8SP1x64):
    """ A Profile for Windows Server 2012 R2 x64 """
    _md_build = 9601 ##FIXME: fake build number to indicate server 2012 R2 vs windows 8.1

class Win8SP0x86(obj.Profile):
    """ A Profile for Windows 8 x86 """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 2
    _md_build = 9200
    _md_vtype_module = 'volatility.plugins.overlays.windows.win8_sp0_x86_vtypes'

class Win8SP1x86(obj.Profile):
    """ A Profile for Windows 8.1 x86 """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 3
    _md_build = 9600
    _md_vtype_module = 'volatility.plugins.overlays.windows.win8_sp1_x86_vtypes'
