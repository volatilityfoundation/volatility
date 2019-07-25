# Volatility
# Copyright (C) 2007-2019 Volatility Foundation
#
# Authors:
# Blaine Stancill <blaine.stancill@FireEye.com>
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

import struct

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.malware.malfind as malfind
import volatility.win32.tasks as tasks

try:
    import yara

    has_yara = True
except ImportError:
    has_yara = False

###############################################################################
# General V-Types
###############################################################################
win10_mem_comp_general_vtypes = {
    '_ST_PAGE_RECORD': [None, {
        'Key': [0x0, ['unsigned int']],
        'CompressedSize': [0x4, ['unsigned short int']],
        'NextKey': [0x4, ['unsigned int']]
    }],
    '_SMKM': [None, {
        'StoreMetaDataPtrArray': [0x0, ['array', 32,
                                        ['pointer', ['array', 32, [
                                            "_SMKM_STORE_METADATA"]]]]]
    }],
    '_SM_GLOBALS': [None, {
        'SmkmStoreMgr': [0x0, ['_SMKM_STORE_MGR']]
    }]
}

###############################################################################
# x86 Specific V-Types
###############################################################################
win10_mem_comp_general_x86_vtypes = {
    '_B_TREE_LEAF_NODE': [0x8, {
        'Key': [0x0, ['unsigned int']],
        'Value': [0x4, ['unsigned int']],
    }],
    '_B_TREE_LEAF': [None, {
        'Elements': [0x0, ['unsigned short int']],
        'Level': [0x2, ['unsigned char']],
        'Leaf': [0x3, ['unsigned char']],
        'LeftChild': [0x4, ['pointer', ['_B_TREE']]],
        'Nodes': [0x8, ['array', lambda x: x.Elements, ['_B_TREE_LEAF_NODE']]]
    }],
    '_B_TREE_NODE': [0x8, {
        'Key': [0x0, ['unsigned int']],
        'Child': [0x4, ['pointer', ['_B_TREE']]]
    }],
    '_B_TREE': [None, {
        'Elements': [0x0, ['unsigned short int']],
        'Level': [0x2, ['unsigned char']],
        'Leaf': [0x3, ['unsigned char']],
        'LeftChild': [0x4, ['pointer', ['_B_TREE']]],
        'Nodes': [0x8, ['array', lambda x: x.Elements, ['_B_TREE_NODE']]]
    }],
    '_SMHP_CHUNK_METADATA': [None, {
        'ChunkPtrArray': [0x0, ['array', 32, ['pointer', ['void']]]],
        'BitValue': [0x88, ['unsigned int']],
        'PageRecordsPerChunkMask': [0x8C, ['unsigned int']],
        'PageRecordSize': [0x90, ['unsigned int']],
        'ChunkPageHeaderSize': [0x98, ['unsigned int']],
    }],
    '_ST_STORE': [None, {
        'StDataMgr': [0x38, ['_ST_DATA_MGR']]
    }],
    '_SMKM_STORE_METADATA': [0x14, {
        'SmkmStore': [0x0, ['pointer', ["_SMKM_STORE"]]],
    }],
    '_SMKM_STORE_MGR': [None, {
        'Smkm': [0x0, ['_SMKM']],
        'KeyToStoreTree': [0xF4, ['pointer', ['_B_TREE']]]
    }]
}

###############################################################################
# x64 Specific V-Types
###############################################################################
win10_mem_comp_general_x64_vtypes = {
    '_B_TREE_LEAF_NODE': [0x8, {
        'Key': [0x0, ['unsigned int']],
        'Value': [0x4, ['unsigned int']],
    }],
    '_B_TREE_LEAF': [None, {
        'Elements': [0x0, ['unsigned short int']],
        'Level': [0x2, ['unsigned char']],
        'Leaf': [0x3, ['unsigned char']],
        'LeftChild': [0x8, ['pointer', ['_B_TREE']]],
        'Nodes': [0x10, ['array', lambda x: x.Elements, ['_B_TREE_LEAF_NODE']]]
    }],
    '_B_TREE_NODE': [0x10, {
        'Key': [0x0, ['unsigned int']],
        'Child': [0x8, ['pointer', ['_B_TREE']]]
    }],
    '_B_TREE': [None, {
        'Elements': [0x0, ['unsigned short int']],
        'Level': [0x2, ['unsigned char']],
        'Leaf': [0x3, ['unsigned char']],
        'LeftChild': [0x8, ['pointer', ['_B_TREE']]],
        'Nodes': [0x10, ['array', lambda x: x.Elements, ['_B_TREE_NODE']]]
    }],
    '_SMHP_CHUNK_METADATA': [None, {
        'ChunkPtrArray': [0x0, ['array', 32, ['pointer', ['void']]]],
        'BitValue': [0x108, ['unsigned int']],
        'PageRecordsPerChunkMask': [0x10C, ['unsigned int']],
        'PageRecordSize': [0x110, ['unsigned int']],
        'ChunkPageHeaderSize': [0x118, ['unsigned int']],
    }],
    '_ST_STORE': [None, {
        'StDataMgr': [0x50, ['_ST_DATA_MGR']]
    }],
    '_SMKM_STORE_METADATA': [0x28, {
        'SmkmStore': [0x0, ['pointer', ["_SMKM_STORE"]]],
    }],
    '_SMKM_STORE_MGR': [None, {
        'Smkm': [0x0, ['_SMKM']],
        'KeyToStoreTree': [0x1C0, ['pointer', ['_B_TREE']]]
    }]
}

###############################################################################
# x64 1903 Specific V-Types
###############################################################################
win10_mem_comp_x64_1903 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3E0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1848, ['pointer', ['void']]],
        'OwnerProcess': [0x19A8, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x86 1903 Specific V-Types
###############################################################################
win10_mem_comp_x86_1903 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x224, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1184, ['pointer', ['void']]],
        'OwnerProcess': [0x1254, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x64 1809 Specific V-Types
###############################################################################
win10_mem_comp_x64_1809 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3E0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1848, ['pointer', ['void']]],
        'OwnerProcess': [0x19A8, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x86 1809 Specific V-Types
###############################################################################
win10_mem_comp_x86_1809 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x224, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1184, ['pointer', ['void']]],
        'OwnerProcess': [0x1254, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x64 1803 Specific V-Types
###############################################################################
win10_mem_comp_x64_1803 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3E0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1848, ['pointer', ['void']]],
        'OwnerProcess': [0x19A8, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x86 1803 Specific V-Types
###############################################################################
win10_mem_comp_x86_1803 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x224, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1184, ['pointer', ['void']]],
        'OwnerProcess': [0x1254, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x64 1709 Specific V-Types
###############################################################################
win10_mem_comp_x64_1709 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3E0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1848, ['pointer', ['void']]],
        'OwnerProcess': [0x19A8, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x86 1709 Specific V-Types
###############################################################################
win10_mem_comp_x86_1709 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x224, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1184, ['pointer', ['void']]],
        'OwnerProcess': [0x1254, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x64 1703 Specific V-Types
###############################################################################
win10_mem_comp_x64_1703 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3D0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1828, ['pointer', ['void']]],
        'OwnerProcess': [0x1988, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x86 1703 Specific V-Types
###############################################################################
win10_mem_comp_x86_1703 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x220, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1174, ['pointer', ['void']]],
        'OwnerProcess': [0x1244, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x64 1607 Specific V-Types
###############################################################################
win10_mem_comp_x64_1607 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3D0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x17A8, ['pointer', ['void']]],
        'OwnerProcess': [0x1918, ['pointer', ["_EPROCESS"]]]
    }]
}

###############################################################################
# x86 1607 Specific V-Types
###############################################################################
win10_mem_comp_x86_1607 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['pointer', ['_B_TREE']]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['pointer', ["_SMKM_STORE"]]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x220, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1124, ['pointer', ['void']]],
        'OwnerProcess': [0x1204, ['pointer', ["_EPROCESS"]]]
    }]
}


###############################################################################
# Add V-Types Based on Conditions
###############################################################################
class Win10MemCompressWin10x641903(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 18362,
                  'memory_model': lambda x: x == '64bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x64_vtypes)
        profile.vtypes.update(win10_mem_comp_x64_1903)


class Win10MemCompressWin10x861903(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 18362,
                  'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x86_vtypes)
        profile.vtypes.update(win10_mem_comp_x86_1903)


class Win10MemCompressWin10x641809(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 17763,
                  'memory_model': lambda x: x == '64bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x64_vtypes)
        profile.vtypes.update(win10_mem_comp_x64_1809)


class Win10MemCompressWin10x861809(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 17763,
                  'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x86_vtypes)
        profile.vtypes.update(win10_mem_comp_x86_1809)


class Win10MemCompressWin10x641803(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 17134,
                  'memory_model': lambda x: x == '64bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x64_vtypes)
        profile.vtypes.update(win10_mem_comp_x64_1803)


class Win10MemCompressWin10x861803(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 17134,
                  'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x86_vtypes)
        profile.vtypes.update(win10_mem_comp_x86_1803)


class Win10MemCompressWin10x641709(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 16299,
                  'memory_model': lambda x: x == '64bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x64_vtypes)
        profile.vtypes.update(win10_mem_comp_x64_1709)


class Win10MemCompressWin10x861709(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 16299,
                  'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x86_vtypes)
        profile.vtypes.update(win10_mem_comp_x86_1709)


class Win10MemCompressWin10x641703(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 15063,
                  'memory_model': lambda x: x == '64bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x64_vtypes)
        profile.vtypes.update(win10_mem_comp_x64_1703)


class Win10MemCompressWin10x861703(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 15063,
                  'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x86_vtypes)
        profile.vtypes.update(win10_mem_comp_x86_1703)


class Win10MemCompressWin10x641607(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 14393,
                  'memory_model': lambda x: x == '64bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x64_vtypes)
        profile.vtypes.update(win10_mem_comp_x64_1607)


class Win10MemCompressWin10x861607(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 14393,
                  'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        profile.vtypes.update(win10_mem_comp_general_vtypes)
        profile.vtypes.update(win10_mem_comp_general_x86_vtypes)
        profile.vtypes.update(win10_mem_comp_x86_1607)


###############################################################################
# Find nt!SmGlobals
###############################################################################
class SmGlobalsStore(object):
    """A class for finding and storing the nt!SmGlobals value"""

    _instance = None

    """
    Below is information about the regexs used to locate nt!SmGlobals:
    
    1607-1709.x86
    8B D1 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB
    SmUpdateMemoryCondition(x,x)+3E   8B D1             mov     edx, ecx
    SmUpdateMemoryCondition(x,x)+40   B9 C0 FA 6A 00    mov     ecx, offset ?SmGlobals@@3U_SM_GLOBALS@@A
    SmUpdateMemoryCondition(x,x)+45   E8 2C 42 02 00    call    ?SmUpdateMemoryConditions@?$SMKM_STORE_MGR@USM_TRAITS@@@@SGXPAU1@W4_SMP_MEMORY_CONDITION@@K@Z
    SmUpdateMemoryCondition(x,x)+4A   EB D5             jmp     short loc_4F2D3D
    SmUpdateMemoryCondition(x,x)+4A                     _SmUpdateMemoryCondition@8 endp
    
    1803-1809.x86
    8B D1 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? EB
    SmUpdateMemoryCondition(x,x)+3D   8B D1             mov     edx, ecx
    SmUpdateMemoryCondition(x,x)+3F   B9 00 EB 6E 00    mov     ecx, offset ?SmGlobals@@3U_SM_GLOBALS@@A ; _SM_GLOBALS SmGlobals
    SmUpdateMemoryCondition(x,x)+44   E8 49 4E 09 00    call    ?SmUpdateMemoryConditions@?$SMKM_STORE_MGR@USM_TRAITS@@@@SGXPAU1@W4_SMP_MEMORY_CONDITION@@K@Z
    SmUpdateMemoryCondition(x,x)+49   5E                pop     esi
    SmUpdateMemoryCondition(x,x)+4A   EB D4             jmp     short loc_4306F8
    SmUpdateMemoryCondition(x,x)+4A                     _SmUpdateMem
    """
    _x86_smglobals = {
        'rules': {
            14393: {
                'sig': "{8B D1 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB}",
                'addr_start': 3,
                'addr_end': 7,
            },
            15063: {
                'sig': "{8B D1 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB}",
                'addr_start': 3,
                'addr_end': 7,
            },
            16299: {
                'sig': "{8B D1 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB}",
                'addr_start': 3,
                'addr_end': 7,
            },
            17134: {
                'sig': "{8B D1 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB}",
                'addr_start': 3,
                'addr_end': 7,
            },
            17763: {
                'sig': "{8B D1 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? EB}",
                'addr_start': 3,
                'addr_end': 7,
            },
            18362: {
                'sig': "{8B D1 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? EB}",
                'addr_start': 3,
                'addr_end': 7,
            }
        }
    }

    """
    Below is information about the regexs used to locate nt!SmGlobals:
    
    *.x64
    4C 8B 02 48 8D ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B
    SmpPageWrite+32   058 4C 8B 02                mov     r8, [rdx]
    SmpPageWrite+35   058 48 8D 0D 10 06 32 00    lea     rcx, qword_1403F71A8
    SmpPageWrite+3C   058 48 8D 15 61 FE 31 00    lea     rdx, ?SmGlobals@@3U_SM_GLOBALS@@A
    SmpPageWrite+43   058 E8 5C 15 FB FF          call    SmpKeyedStoreReference
    SmpPageWrite+48   058 8B F8                   mov     edi, eax
    """
    _x64_smglobals = {
        'rules': {
            14393: {
                'sig': ("{4C 8B 02 48 8D ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? "
                        "E8 ?? ?? ?? ?? 8B}"),
                'addr_start': 13,
                'addr_end': 17
            },
            15063: {
                'sig': ("{4C 8B 02 48 8D ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? "
                        "E8 ?? ?? ?? ?? 8B}"),
                'addr_start': 13,
                'addr_end': 17
            },
            16299: {
                'sig': ("{4C 8B 02 48 8D ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? "
                        "E8 ?? ?? ?? ?? 8B}"),
                'addr_start': 13,
                'addr_end': 17
            },
            17134: {
                'sig': ("{4C 8B 02 48 8D ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? "
                        "E8 ?? ?? ?? ?? 8B}"),
                'addr_start': 13,
                'addr_end': 17
            },
            17763: {
                'sig': ("{4C 8B 02 48 8D ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? "
                        "E8 ?? ?? ?? ?? 8B}"),
                'addr_start': 13,
                'addr_end': 17
            },
            18362: {
                'sig': ("{4C 8B 02 48 8D ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? "
                        "E8 ?? ?? ?? ?? 8B}"),
                'addr_start': 13,
                'addr_end': 17
            }
        }
    }

    def __init__(self):
        self._smglobals = None

    def smglobals(self):
        return self._smglobals

    def _yara_scan(self, addrspace, rule, start, end):
        rules = yara.compile(sources = {
            'n': 'rule r1 {strings: $a = ' + rule + ' condition: $a}'
        })

        scanner = malfind.DiscontigYaraScanner(address_space = addrspace,
                                               rules = rules)

        scan_results = scanner.scan(start_offset = start, maxlen = end)

        try:
            hit, addr = next(scan_results)
        except StopIteration:
            return None, None

        return hit, addr

    def _to_signed(self, x, b = 32):
        if x >> (b - 1):  # is the highest bit set?
            return x - (1 << b)  # 2's complement
        return x

    def _get_smglobals(self, addrspace, nt_mod, meta):
        # Define range for finding SmGlobals with Yara
        nt_start = nt_mod.DllBase
        nt_end = nt_mod.SizeOfImage

        build = addrspace.profile.metadata.get('build', 14393)
        rule = meta['rules'][build]

        hit, addr = self._yara_scan(addrspace, rule['sig'], nt_start, nt_end)
        if not addr or not nt_mod.obj_vm.is_valid_address(addr):
            return None

        # Extract the SmGlobals address from the regex hit
        start = rule['addr_start']
        end = rule['addr_end']
        sm_addr = struct.unpack("<I", hit.strings[0][2][start:end])[0]

        if addrspace.profile.metadata.get('memory_model', '32bit') == '64bit':
            # Use ntoskrnl's base address to extend address from 48 to 64 bits
            addr |= (nt_start >> addr.bit_length()) << addr.bit_length()

            # Use RIP-relative addressing
            smglobals = addr + end + self._to_signed(sm_addr)
        else:
            smglobals = sm_addr

        # Check if SmGlobals is valid and within bounds of ntoskrnl
        if (not nt_mod.obj_vm.is_valid_address(smglobals)
                or smglobals > (nt_start + nt_end)
                or smglobals < nt_start):
            return None

        return smglobals

    def find_smglobals(self, addrspace):
        """Find and read the nt!SmGlobals value.

        On success, return True and save the SmGlobals value in
        self._smglobals. On Failure, return False.

        This method must be called before performing any tasks that require
        SmGlobals. Otherwise reading compressed pages is out of the question.
        """
        meta = addrspace.profile.metadata
        vers = (meta.get("major", 0), meta.get("minor", 0))

        # This only applies to Windows 10 or greater
        if vers < (6, 4):
            return False

        # Prevent subsequent attempts from recalculating the existing value
        if self._smglobals:
            return True

        if not has_yara:
            debug.warning("Yara module is not installed")
            return False

        kdbg = tasks.get_kdbg(addrspace)
        if not kdbg:
            debug.warning("Cannot find KDBG")
            return False

        # First module should be ntoskrnl
        try:
            nt_mod = next(kdbg.modules())
        except StopIteration:
            debug.warning("Cannot find ntoskrnl")
            return False

        if not nt_mod:
            debug.warning("Cannot find ntoskrnl")
            return False

        if meta.get('memory_model', '32bit') == '32bit':
            smglobals = self._get_smglobals(addrspace, nt_mod,
                                            self._x86_smglobals)
        else:
            smglobals = self._get_smglobals(addrspace, nt_mod,
                                            self._x64_smglobals)

        self._smglobals = smglobals
        return True

    @staticmethod
    def instance():
        if not SmGlobalsStore._instance:
            SmGlobalsStore._instance = SmGlobalsStore()

        return SmGlobalsStore._instance


class VolatilitySmGlobals(obj.VolatilityMagic):
    """The Windows 10 SmGlobals Finder"""

    def generate_suggestions(self):
        store = SmGlobalsStore.instance()
        store.find_smglobals(self.obj_vm)
        yield store.smglobals()


class Win10SmGlobals(obj.ProfileModification):
    """The Windows 10 SmGlobals Finder"""

    before = ['WindowsOverlay']

    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x in [14393, 15063, 16299, 17134, 17763,
                                           18362]}

    def modification(self, profile):
        profile.merge_overlay(
            {'VOLATILITY_MAGIC': [None, {'SmGlobals': [0x0, [
                'VolatilitySmGlobals', dict(configname = "SMGLOBALS")]]}]})
        profile.object_classes.update(
            {'VolatilitySmGlobals': VolatilitySmGlobals})


class Win10VSPageFileNumber(obj.ProfileModification):
    """The Windows 10 Virtual Store Page File Number"""

    before = ['WindowsOverlay']

    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x in [14393, 15063, 16299, 17134, 17763,
                                           18362]}

    def modification(self, profile):
        profile.merge_overlay(
            {'VOLATILITY_MAGIC': [None, {'VSPageFileNumber': [0x0, [
                'VolatilityMagic',
                dict(configname = "VSPAGEFILENUMBER", value = 2)]]}]})


class Win10DisableMemCompression(obj.ProfileModification):
    """Disables Windows 10 memory decompression address spaces if set"""

    before = ['WindowsOverlay']

    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x in [14393, 15063, 16299, 17134, 17763,
                                           18362]}

    def modification(self, profile):
        profile.merge_overlay(
            {'VOLATILITY_MAGIC': [None, {'DisableWin10MemCompress': [0x0, [
                'VolatilityMagic',
                dict(configname = "DISABLEWIN10MEMCOMPRESS", value = False)
            ]]}]})
