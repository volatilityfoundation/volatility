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

import os
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.win32.modules as modules

import volatility.win32.tasks as tasks
import volatility.plugins.filescan as filescan
import volatility.plugins.malware.devicetree as devicetree
import volatility.plugins.malware.svcscan as svcscan
import volatility.plugins.registry.registryapi as registryapi

tc_70a_vtypes_x86 = {
  'UINT64_STRUCT' : [ 0x8, {
    'LowPart' : [ 0x0, ['unsigned long']],
    'HighPart' : [ 0x4, ['unsigned long']],
    'Value' : [ 0x0, ['unsigned long long']],
    } ],
  'CRYPTO_INFO_t' : [ 0x4468, {
    'ea' : [ 0x0, ['long']],
    'mode' : [ 0x4, ['long']],
    'ks' : [ 0x8, ['array', 5324, ['unsigned char']]],
    'ks2' : [ 0x14d4, ['array', 5324, ['unsigned char']]],
    'hiddenVolume' : [ 0x29a0, ['long']],
    'HeaderVersion' : [ 0x29a4, ['unsigned short']],
    'gf_ctx' : [ 0x29a8, ['GfCtx']],
    'master_keydata' : [ 0x41a8, ['array', 256, ['unsigned char']]],
    'k2' : [ 0x42a8, ['array', 256, ['unsigned char']]],
    'salt' : [ 0x43a8, ['array', 64, ['unsigned char']]],
    'noIterations' : [ 0x43e8, ['long']],
    'pkcs5' : [ 0x43ec, ['long']],
    'volume_creation_time' : [ 0x43f0, ['unsigned long long']],
    'header_creation_time' : [ 0x43f8, ['unsigned long long']],
    'bProtectHiddenVolume' : [ 0x4400, ['long']],
    'bHiddenVolProtectionAction' : [ 0x4404, ['long']],
    'volDataAreaOffset' : [ 0x4408, ['unsigned long long']],
    'hiddenVolumeSize' : [ 0x4410, ['unsigned long long']],
    'hiddenVolumeOffset' : [ 0x4418, ['unsigned long long']],
    'hiddenVolumeProtectedSize' : [ 0x4420, ['unsigned long long']],
    'bPartitionInInactiveSysEncScope' : [ 0x4428, ['long']],
    'FirstDataUnitNo' : [ 0x4430, ['UINT64_STRUCT']],
    'RequiredProgramVersion' : [ 0x4438, ['unsigned short']],
    'LegacyVolume' : [ 0x443c, ['long']],
    'SectorSize' : [ 0x4440, ['unsigned long']],
    'VolumeSize' : [ 0x4448, ['UINT64_STRUCT']],
    'EncryptedAreaStart' : [ 0x4450, ['UINT64_STRUCT']],
    'EncryptedAreaLength' : [ 0x4458, ['UINT64_STRUCT']],
    'HeaderFlags' : [ 0x4460, ['unsigned long']],
    } ],
  'Password' : [ 0x48, {
    'Length' : [ 0x0, ['unsigned long']],
    'Text' : [ 0x4, ['array', 65, ['unsigned char']]],
    'Pad' : [ 0x45, ['array', 3, ['unsigned char']]],
    } ],
  'EXTENSION' : [ 0x510, {
    'bRootDevice' : [ 0x0, ['long']],
    'IsVolumeDevice' : [ 0x4, ['long']],
    'IsDriveFilterDevice' : [ 0x8, ['long']],
    'IsVolumeFilterDevice' : [ 0xc, ['long']],
    'lMagicNumber' : [ 0x10, ['unsigned long']],
    'UniqueVolumeId' : [ 0x14, ['long']],
    'nDosDriveNo' : [ 0x18, ['long']],
    'bShuttingDown' : [ 0x1c, ['long']],
    'bThreadShouldQuit' : [ 0x20, ['long']],
    'peThread' : [ 0x24, ['pointer', ['_KTHREAD']]],
    'keCreateEvent' : [ 0x28, ['_KEVENT']],
    'ListSpinLock' : [ 0x38, ['unsigned long']],
    'ListEntry' : [ 0x3c, ['_LIST_ENTRY']],
    'RequestSemaphore' : [ 0x44, ['_KSEMAPHORE']],
    'hDeviceFile' : [ 0x58, ['pointer', ['void']]],
    'pfoDeviceFile' : [ 0x5c, ['pointer', ['_FILE_OBJECT']]],
    'pFsdDevice' : [ 0x60, ['pointer', ['_DEVICE_OBJECT']]],
    'cryptoInfo' : [ 0x64, ['pointer', ['CRYPTO_INFO_t']]],
    'HostLength' : [ 0x68, ['long long']],
    'DiskLength' : [ 0x70, ['long long']],
    'NumberOfCylinders' : [ 0x78, ['long long']],
    'TracksPerCylinder' : [ 0x80, ['unsigned long']],
    'SectorsPerTrack' : [ 0x84, ['unsigned long']],
    'BytesPerSector' : [ 0x88, ['unsigned long']],
    'PartitionType' : [ 0x8c, ['unsigned char']],
    'HostBytesPerSector' : [ 0x90, ['unsigned long']],
    'keVolumeEvent' : [ 0x94, ['_KEVENT']],
    'Queue' : [ 0xa8, ['EncryptedIoQueue']],
    'bReadOnly' : [ 0x288, ['long']],
    'bRemovable' : [ 0x28c, ['long']],
    'PartitionInInactiveSysEncScope' : [ 0x290, ['long']],
    'bRawDevice' : [ 0x294, ['long']],
    'bMountManager' : [ 0x298, ['long']],
    'SystemFavorite' : [ 0x29c, ['long']],
    'wszVolume' : [ 0x2a0, ['array', 260, ['wchar']]],
    'fileCreationTime' : [ 0x4a8, ['_LARGE_INTEGER']],
    'fileLastAccessTime' : [ 0x4b0, ['_LARGE_INTEGER']],
    'fileLastWriteTime' : [ 0x4b8, ['_LARGE_INTEGER']],
    'fileLastChangeTime' : [ 0x4c0, ['_LARGE_INTEGER']],
    'bTimeStampValid' : [ 0x4c8, ['long']],
    'UserSid' : [ 0x4cc, ['pointer', ['void']]],
    'SecurityClientContextValid' : [ 0x4d0, ['long']],
    'SecurityClientContext' : [ 0x4d4, ['_SECURITY_CLIENT_CONTEXT']],
    } ],
}

tc_71a_vtypes_x86 = {
  'UINT64_STRUCT' : [ 0x8, {
    'LowPart' : [ 0x0, ['unsigned long']],
    'HighPart' : [ 0x4, ['unsigned long']],
    'Value' : [ 0x0, ['unsigned long long']],
    } ],
  'CRYPTO_INFO_t' : [ 0x4468, {
    'ea' : [ 0x0, ['long']],
    'mode' : [ 0x4, ['long']],
    'ks' : [ 0x8, ['array', 5324, ['unsigned char']]],
    'ks2' : [ 0x14d4, ['array', 5324, ['unsigned char']]],
    'hiddenVolume' : [ 0x29a0, ['long']],
    'HeaderVersion' : [ 0x29a4, ['unsigned short']],
    'gf_ctx' : [ 0x29a8, ['GfCtx']],
    'master_keydata' : [ 0x41a8, ['array', 256, ['unsigned char']]],
    'k2' : [ 0x42a8, ['array', 256, ['unsigned char']]],
    'salt' : [ 0x43a8, ['array', 64, ['unsigned char']]],
    'noIterations' : [ 0x43e8, ['long']],
    'pkcs5' : [ 0x43ec, ['long']],
    'volume_creation_time' : [ 0x43f0, ['unsigned long long']],
    'header_creation_time' : [ 0x43f8, ['unsigned long long']],
    'bProtectHiddenVolume' : [ 0x4400, ['long']],
    'bHiddenVolProtectionAction' : [ 0x4404, ['long']],
    'volDataAreaOffset' : [ 0x4408, ['unsigned long long']],
    'hiddenVolumeSize' : [ 0x4410, ['unsigned long long']],
    'hiddenVolumeOffset' : [ 0x4418, ['unsigned long long']],
    'hiddenVolumeProtectedSize' : [ 0x4420, ['unsigned long long']],
    'bPartitionInInactiveSysEncScope' : [ 0x4428, ['long']],
    'FirstDataUnitNo' : [ 0x4430, ['UINT64_STRUCT']],
    'RequiredProgramVersion' : [ 0x4438, ['unsigned short']],
    'LegacyVolume' : [ 0x443c, ['long']],
    'SectorSize' : [ 0x4440, ['unsigned long']],
    'VolumeSize' : [ 0x4448, ['UINT64_STRUCT']],
    'EncryptedAreaStart' : [ 0x4450, ['UINT64_STRUCT']],
    'EncryptedAreaLength' : [ 0x4458, ['UINT64_STRUCT']],
    'HeaderFlags' : [ 0x4460, ['unsigned long']],
    } ],
  'EXTENSION' : [ 0x4d0, {
    'bRootDevice' : [ 0x0, ['long']],
    'IsVolumeDevice' : [ 0x4, ['long']],
    'IsDriveFilterDevice' : [ 0x8, ['long']],
    'IsVolumeFilterDevice' : [ 0xc, ['long']],
    'UniqueVolumeId' : [ 0x10, ['long']],
    'nDosDriveNo' : [ 0x14, ['long']],
    'bShuttingDown' : [ 0x18, ['long']],
    'bThreadShouldQuit' : [ 0x1c, ['long']],
    'peThread' : [ 0x20, ['pointer', ['_KTHREAD']]],
    'keCreateEvent' : [ 0x24, ['_KEVENT']],
    'ListSpinLock' : [ 0x34, ['unsigned long']],
    'ListEntry' : [ 0x38, ['_LIST_ENTRY']],
    'RequestSemaphore' : [ 0x40, ['_KSEMAPHORE']],
    'hDeviceFile' : [ 0x54, ['pointer', ['void']]],
    'pfoDeviceFile' : [ 0x58, ['pointer', ['_FILE_OBJECT']]],
    'pFsdDevice' : [ 0x5c, ['pointer', ['_DEVICE_OBJECT']]],
    'cryptoInfo' : [ 0x60, ['pointer', ['CRYPTO_INFO_t']]],
    'HostLength' : [ 0x68, ['long long']],
    'DiskLength' : [ 0x70, ['long long']],
    'NumberOfCylinders' : [ 0x78, ['long long']],
    'TracksPerCylinder' : [ 0x80, ['unsigned long']],
    'SectorsPerTrack' : [ 0x84, ['unsigned long']],
    'BytesPerSector' : [ 0x88, ['unsigned long']],
    'PartitionType' : [ 0x8c, ['unsigned char']],
    'HostBytesPerSector' : [ 0x90, ['unsigned long']],
    'keVolumeEvent' : [ 0x94, ['_KEVENT']],
    'Queue' : [ 0xa8, ['EncryptedIoQueue']],
    'bReadOnly' : [ 0x248, ['long']],
    'bRemovable' : [ 0x24c, ['long']],
    'PartitionInInactiveSysEncScope' : [ 0x250, ['long']],
    'bRawDevice' : [ 0x254, ['long']],
    'bMountManager' : [ 0x258, ['long']],
    'SystemFavorite' : [ 0x25c, ['long']],
    'wszVolume' : [ 0x260, ['array', 260, ['wchar']]],
    'fileCreationTime' : [ 0x468, ['_LARGE_INTEGER']],
    'fileLastAccessTime' : [ 0x470, ['_LARGE_INTEGER']],
    'fileLastWriteTime' : [ 0x478, ['_LARGE_INTEGER']],
    'fileLastChangeTime' : [ 0x480, ['_LARGE_INTEGER']],
    'bTimeStampValid' : [ 0x488, ['long']],
    'UserSid' : [ 0x48c, ['pointer', ['void']]],
    'SecurityClientContextValid' : [ 0x490, ['long']],
    'SecurityClientContext' : [ 0x494, ['_SECURITY_CLIENT_CONTEXT']],
    } ],
  'Password' : [ 0x48, {
    'Length' : [ 0x0, ['unsigned long']],
    'Text' : [ 0x4, ['array', 65, ['unsigned char']]],
    'Pad' : [ 0x45, ['array', 3, ['unsigned char']]],
    } ],
}

tc_70a_vtypes_x64 = {
  'UINT64_STRUCT' : [ 0x8, {
    'LowPart' : [ 0x0, ['unsigned long']],
    'HighPart' : [ 0x4, ['unsigned long']],
    'Value' : [ 0x0, ['unsigned long long']],
    } ],
  'CRYPTO_INFO_t' : [ 0x4468, {
    'ea' : [ 0x0, ['long']],
    'mode' : [ 0x4, ['long']],
    'ks' : [ 0x8, ['array', 5324, ['unsigned char']]],
    'ks2' : [ 0x14d4, ['array', 5324, ['unsigned char']]],
    'hiddenVolume' : [ 0x29a0, ['long']],
    'HeaderVersion' : [ 0x29a4, ['unsigned short']],
    'gf_ctx' : [ 0x29a8, ['GfCtx']],
    'master_keydata' : [ 0x41a8, ['array', 256, ['unsigned char']]],
    'k2' : [ 0x42a8, ['array', 256, ['unsigned char']]],
    'salt' : [ 0x43a8, ['array', 64, ['unsigned char']]],
    'noIterations' : [ 0x43e8, ['long']],
    'pkcs5' : [ 0x43ec, ['long']],
    'volume_creation_time' : [ 0x43f0, ['unsigned long long']],
    'header_creation_time' : [ 0x43f8, ['unsigned long long']],
    'bProtectHiddenVolume' : [ 0x4400, ['long']],
    'bHiddenVolProtectionAction' : [ 0x4404, ['long']],
    'volDataAreaOffset' : [ 0x4408, ['unsigned long long']],
    'hiddenVolumeSize' : [ 0x4410, ['unsigned long long']],
    'hiddenVolumeOffset' : [ 0x4418, ['unsigned long long']],
    'hiddenVolumeProtectedSize' : [ 0x4420, ['unsigned long long']],
    'bPartitionInInactiveSysEncScope' : [ 0x4428, ['long']],
    'FirstDataUnitNo' : [ 0x4430, ['UINT64_STRUCT']],
    'RequiredProgramVersion' : [ 0x4438, ['unsigned short']],
    'LegacyVolume' : [ 0x443c, ['long']],
    'SectorSize' : [ 0x4440, ['unsigned long']],
    'VolumeSize' : [ 0x4448, ['UINT64_STRUCT']],
    'EncryptedAreaStart' : [ 0x4450, ['UINT64_STRUCT']],
    'EncryptedAreaLength' : [ 0x4458, ['UINT64_STRUCT']],
    'HeaderFlags' : [ 0x4460, ['unsigned long']],
    } ],
  'EXTENSION' : [ 0x640, {
    'bRootDevice' : [ 0x0, ['long']],
    'IsVolumeDevice' : [ 0x4, ['long']],
    'IsDriveFilterDevice' : [ 0x8, ['long']],
    'IsVolumeFilterDevice' : [ 0xc, ['long']],
    'lMagicNumber' : [ 0x10, ['unsigned long']],
    'UniqueVolumeId' : [ 0x14, ['long']],
    'nDosDriveNo' : [ 0x18, ['long']],
    'bShuttingDown' : [ 0x1c, ['long']],
    'bThreadShouldQuit' : [ 0x20, ['long']],
    'peThread' : [ 0x28, ['pointer64', ['_KTHREAD']]],
    'keCreateEvent' : [ 0x30, ['_KEVENT']],
    'ListSpinLock' : [ 0x48, ['unsigned long long']],
    'ListEntry' : [ 0x50, ['_LIST_ENTRY']],
    'RequestSemaphore' : [ 0x60, ['_KSEMAPHORE']],
    'hDeviceFile' : [ 0x80, ['pointer64', ['void']]],
    'pfoDeviceFile' : [ 0x88, ['pointer64', ['_FILE_OBJECT']]],
    'pFsdDevice' : [ 0x90, ['pointer64', ['_DEVICE_OBJECT']]],
    'cryptoInfo' : [ 0x98, ['pointer64', ['CRYPTO_INFO_t']]],
    'HostLength' : [ 0xa0, ['long long']],
    'DiskLength' : [ 0xa8, ['long long']],
    'NumberOfCylinders' : [ 0xb0, ['long long']],
    'TracksPerCylinder' : [ 0xb8, ['unsigned long']],
    'SectorsPerTrack' : [ 0xbc, ['unsigned long']],
    'BytesPerSector' : [ 0xc0, ['unsigned long']],
    'PartitionType' : [ 0xc4, ['unsigned char']],
    'HostBytesPerSector' : [ 0xc8, ['unsigned long']],
    'keVolumeEvent' : [ 0xd0, ['_KEVENT']],
    'Queue' : [ 0xe8, ['EncryptedIoQueue']],
    'bReadOnly' : [ 0x3a0, ['long']],
    'bRemovable' : [ 0x3a4, ['long']],
    'PartitionInInactiveSysEncScope' : [ 0x3a8, ['long']],
    'bRawDevice' : [ 0x3ac, ['long']],
    'bMountManager' : [ 0x3b0, ['long']],
    'SystemFavorite' : [ 0x3b4, ['long']],
    'wszVolume' : [ 0x3b8, ['array', 260, ['wchar']]],
    'fileCreationTime' : [ 0x5c0, ['_LARGE_INTEGER']],
    'fileLastAccessTime' : [ 0x5c8, ['_LARGE_INTEGER']],
    'fileLastWriteTime' : [ 0x5d0, ['_LARGE_INTEGER']],
    'fileLastChangeTime' : [ 0x5d8, ['_LARGE_INTEGER']],
    'bTimeStampValid' : [ 0x5e0, ['long']],
    'UserSid' : [ 0x5e8, ['pointer64', ['void']]],
    'SecurityClientContextValid' : [ 0x5f0, ['long']],
    'SecurityClientContext' : [ 0x5f8, ['_SECURITY_CLIENT_CONTEXT']],
    } ],
  'Password' : [ 0x48, {
    'Length' : [ 0x0, ['unsigned long']],
    'Text' : [ 0x4, ['array', 65, ['unsigned char']]],
    'Pad' : [ 0x45, ['array', 3, ['unsigned char']]],
    } ],
}
    
tc_71a_vtypes_x64 = {
  'UINT64_STRUCT' : [ 0x8, {
    'LowPart' : [ 0x0, ['unsigned long']],
    'HighPart' : [ 0x4, ['unsigned long']],
    'Value' : [ 0x0, ['unsigned long long']],
    } ],
  'CRYPTO_INFO_t' : [ 0x4468, {
    'ea' : [ 0x0, ['long']],
    'mode' : [ 0x4, ['long']],
    'ks' : [ 0x8, ['array', 5324, ['unsigned char']]],
    'ks2' : [ 0x14d4, ['array', 5324, ['unsigned char']]],
    'hiddenVolume' : [ 0x29a0, ['long']],
    'HeaderVersion' : [ 0x29a4, ['unsigned short']],
    'gf_ctx' : [ 0x29a8, ['GfCtx']],
    'master_keydata' : [ 0x41a8, ['array', 256, ['unsigned char']]],
    'k2' : [ 0x42a8, ['array', 256, ['unsigned char']]],
    'salt' : [ 0x43a8, ['array', 64, ['unsigned char']]],
    'noIterations' : [ 0x43e8, ['long']],
    'pkcs5' : [ 0x43ec, ['long']],
    'volume_creation_time' : [ 0x43f0, ['unsigned long long']],
    'header_creation_time' : [ 0x43f8, ['unsigned long long']],
    'bProtectHiddenVolume' : [ 0x4400, ['long']],
    'bHiddenVolProtectionAction' : [ 0x4404, ['long']],
    'volDataAreaOffset' : [ 0x4408, ['unsigned long long']],
    'hiddenVolumeSize' : [ 0x4410, ['unsigned long long']],
    'hiddenVolumeOffset' : [ 0x4418, ['unsigned long long']],
    'hiddenVolumeProtectedSize' : [ 0x4420, ['unsigned long long']],
    'bPartitionInInactiveSysEncScope' : [ 0x4428, ['long']],
    'FirstDataUnitNo' : [ 0x4430, ['UINT64_STRUCT']],
    'RequiredProgramVersion' : [ 0x4438, ['unsigned short']],
    'LegacyVolume' : [ 0x443c, ['long']],
    'SectorSize' : [ 0x4440, ['unsigned long']],
    'VolumeSize' : [ 0x4448, ['UINT64_STRUCT']],
    'EncryptedAreaStart' : [ 0x4450, ['UINT64_STRUCT']],
    'EncryptedAreaLength' : [ 0x4458, ['UINT64_STRUCT']],
    'HeaderFlags' : [ 0x4460, ['unsigned long']],
    } ],
  'Password' : [ 0x48, {
    'Length' : [ 0x0, ['unsigned long']],
    'Text' : [ 0x4, ['array', 65, ['unsigned char']]],
    'Pad' : [ 0x45, ['array', 3, ['unsigned char']]],
    } ],
  'EXTENSION' : [ 0x5e0, {
    'bRootDevice' : [ 0x0, ['long']],
    'IsVolumeDevice' : [ 0x4, ['long']],
    'IsDriveFilterDevice' : [ 0x8, ['long']],
    'IsVolumeFilterDevice' : [ 0xc, ['long']],
    'UniqueVolumeId' : [ 0x10, ['long']],
    'nDosDriveNo' : [ 0x14, ['long']],
    'bShuttingDown' : [ 0x18, ['long']],
    'bThreadShouldQuit' : [ 0x1c, ['long']],
    'peThread' : [ 0x20, ['pointer64', ['_KTHREAD']]],
    'keCreateEvent' : [ 0x28, ['_KEVENT']],
    'ListSpinLock' : [ 0x40, ['unsigned long long']],
    'ListEntry' : [ 0x48, ['_LIST_ENTRY']],
    'RequestSemaphore' : [ 0x58, ['_KSEMAPHORE']],
    'hDeviceFile' : [ 0x78, ['pointer64', ['void']]],
    'pfoDeviceFile' : [ 0x80, ['pointer64', ['_FILE_OBJECT']]],
    'pFsdDevice' : [ 0x88, ['pointer64', ['_DEVICE_OBJECT']]],
    'cryptoInfo' : [ 0x90, ['pointer64', ['CRYPTO_INFO_t']]],
    'HostLength' : [ 0x98, ['long long']],
    'DiskLength' : [ 0xa0, ['long long']],
    'NumberOfCylinders' : [ 0xa8, ['long long']],
    'TracksPerCylinder' : [ 0xb0, ['unsigned long']],
    'SectorsPerTrack' : [ 0xb4, ['unsigned long']],
    'BytesPerSector' : [ 0xb8, ['unsigned long']],
    'PartitionType' : [ 0xbc, ['unsigned char']],
    'HostBytesPerSector' : [ 0xc0, ['unsigned long']],
    'keVolumeEvent' : [ 0xc8, ['_KEVENT']],
    'Queue' : [ 0xe0, ['EncryptedIoQueue']],
    'bReadOnly' : [ 0x340, ['long']],
    'bRemovable' : [ 0x344, ['long']],
    'PartitionInInactiveSysEncScope' : [ 0x348, ['long']],
    'bRawDevice' : [ 0x34c, ['long']],
    'bMountManager' : [ 0x350, ['long']],
    'SystemFavorite' : [ 0x354, ['long']],
    'wszVolume' : [ 0x358, ['array', 260, ['wchar']]],
    'fileCreationTime' : [ 0x560, ['_LARGE_INTEGER']],
    'fileLastAccessTime' : [ 0x568, ['_LARGE_INTEGER']],
    'fileLastWriteTime' : [ 0x570, ['_LARGE_INTEGER']],
    'fileLastChangeTime' : [ 0x578, ['_LARGE_INTEGER']],
    'bTimeStampValid' : [ 0x580, ['long']],
    'UserSid' : [ 0x588, ['pointer64', ['void']]],
    'SecurityClientContextValid' : [ 0x590, ['long']],
    'SecurityClientContext' : [ 0x598, ['_SECURITY_CLIENT_CONTEXT']],
    } ],
}

#---------------------------------------------------------------------
# TrueCryptPassphrase Plugin
#---------------------------------------------------------------------
            
class TrueCryptPassphrase(common.AbstractWindowsCommand):
    """TrueCrypt Cached Passprhase Finder"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('MIN-LENGTH', short_option = 'M', default = 5,
                          help = 'Mimumim length of passphrases to identify',
                          action = 'store', type = 'int')

    def calculate(self):
        addr_space = utils.load_as(self._config)

        for mod in modules.lsmod(addr_space):

            # Finding the TC kernel module
            if str(mod.BaseDllName).lower() != "truecrypt.sys":
                continue

            dos_header = obj.Object("_IMAGE_DOS_HEADER", 
                                    offset = mod.DllBase, 
                                    vm = addr_space)
            nt_header = dos_header.get_nt_header()

            # Finding the PE data section 
            data_section = None
            for sec in nt_header.get_sections():
                if str(sec.Name) == ".data":
                    data_section = sec
                    break
 
            if not data_section:
                break

            base = sec.VirtualAddress + mod.DllBase
            size = sec.Misc.VirtualSize

            # Looking for the Length member, DWORD-aligned 
            ints = obj.Object("Array", targetType = "int", 
                              offset = base, count = size / 4, 
                              vm = addr_space)
        
            for length in ints:
                # Min and max passphrase lengths 
                if length >= self._config.MIN_LENGTH and length <= 64:
                    offset = length.obj_offset + 4
                    passphrase = addr_space.read(offset, length)
                    if not passphrase:
                        continue
                    # All characters in the range must be ASCII
                    chars = [c for c in passphrase if ord(c) >= 0x20 and ord(c) <= 0x7F]
                    if len(chars) != length:
                        continue
                    # At least three zero-bad bytes must follow 
                    if addr_space.read(offset + length, 3) != "\x00" * 3:
                        continue
                    yield offset, passphrase 

    def render_text(self, outfd, data):
        for offset, passphrase in data:
            outfd.write("Found at {0:#x} length {1}: {2}\n".format(
                offset, len(passphrase), passphrase))

#---------------------------------------------------------------------
# TrueCryptSummary Plugin
#---------------------------------------------------------------------

class TrueCryptSummary(common.AbstractWindowsCommand):
    """TrueCrypt Summary"""

    def calculate(self):
        addr_space = utils.load_as(self._config)

        # we currently don't use this on x64 because for some reason the 
        # x64 version actually doesn't create a DisplayVersion value 
        memory_model = addr_space.profile.metadata.get('memory_model')
        if memory_model == '32bit':
            regapi = registryapi.RegistryApi(self._config)
            regapi.reset_current()
            regapi.set_current(hive_name = "software")
            x86key = "Microsoft\\Windows\\CurrentVersion\\Uninstall"
            x64key = "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
            for subkey in regapi.reg_get_all_subkeys(None, key = x86key):
                if str(subkey.Name) == "TrueCrypt":
                    subpath = x86key + "\\" + subkey.Name
                    version = regapi.reg_get_value("software", 
                                            key = subpath, 
                                            value = "DisplayVersion")
                    if version:
                        yield "Registry Version", "{0} Version {1}".format(
                            str(subkey.Name),
                            version)

        scanner = TrueCryptPassphrase(self._config)
        for offset, passphrase in scanner.calculate():
            yield "Password", "{0} at offset {1:#x}".format(
                        passphrase, offset)

        for proc in tasks.pslist(addr_space):
            if str(proc.ImageFileName).lower() == "truecrypt.exe":     
                yield "Process", "{0} at {1:#x} pid {2}".format(
                        proc.ImageFileName,
                        proc.obj_offset, 
                        proc.UniqueProcessId)   

        scanner = svcscan.SvcScan(self._config)
        for service in scanner.calculate():
            name = str(service.ServiceName.dereference())
            if name == "truecrypt":
                yield "Service", "{0} state {1}".format(
                        name, 
                        service.State)

        for mod in modules.lsmod(addr_space):
            basename = str(mod.BaseDllName or '').lower()
            fullname = str(mod.FullDllName or '').lower()
            if (basename.endswith("truecrypt.sys") or 
                        fullname.endswith("truecrypt.sys")):
                yield "Kernel Module",  "{0} at {1:#x} - {2:#x}".format(
                        mod.BaseDllName, 
                        mod.DllBase, 
                        mod.DllBase + mod.SizeOfImage)

        scanner = filescan.SymLinkScan(self._config)
        for symlink in scanner.calculate():
            object_header = symlink.get_object_header()
            if "TrueCryptVolume" in str(symlink.LinkTarget or ''):
                yield "Symbolic Link", "{0} -> {1} mounted {2}".format(
                        str(object_header.NameInfo.Name or ''), 
                        str(symlink.LinkTarget or ''), 
                        str(symlink.CreationTime or ''))

        scanner = filescan.FileScan(self._config)
        for fileobj in scanner.calculate():
            filename = str(fileobj.file_name_with_device() or '')
            if "TrueCryptVolume" in filename:
                yield "File Object", "{0} at {1:#x}".format(
                        filename,
                        fileobj.obj_offset)
        
        scanner = filescan.DriverScan(self._config)
        for driver in scanner.calculate():
            object_header = driver.get_object_header() 
            driverext = driver.DriverExtension
            drivername = str(driver.DriverName or '')
            servicekey = str(driverext.ServiceKeyName or '')
            if (drivername.endswith("truecrypt") or 
                        servicekey.endswith("truecrypt")):
                yield "Driver", "{0} at {1:#x} range {2:#x} - {3:#x}".format(
                        drivername, 
                        driver.obj_offset, 
                        driver.DriverStart, 
                        driver.DriverStart + driver.DriverSize)
                for device in driver.devices():
                    header = device.get_object_header()
                    devname = str(header.NameInfo.Name or '')
                    type = devicetree.DEVICE_CODES.get(device.DeviceType.v())
                    yield "Device", "{0} at {1:#x} type {2}".format(
                        devname or "<HIDDEN>", 
                        device.obj_offset, 
                        type or "UNKNOWN")
                    if type == "FILE_DEVICE_DISK":
                        data = addr_space.read(device.DeviceExtension, 2000)
                        ## the file-hosted container path. no other fields in
                        ## the struct are character based, so we should not 
                        ## hit false positives on this scan. 
                        offset = data.find("\\\x00?\x00?\x00\\\x00")
                        if offset == -1:
                            container = "<HIDDEN>"
                        else:
                            container = obj.Object("String", length = 255, 
                                        offset = device.DeviceExtension + offset, 
                                        encoding = "utf16",
                                        vm = addr_space)
                        yield "Container", "Path: {0}".format(container)

    def render_text(self, outfd, data):
        for field, info in data:
            outfd.write("{0:20} {1}\n".format(field, info))

#---------------------------------------------------------------------
# TrueCryptMaster Plugin
#---------------------------------------------------------------------

class TrueCryptMaster(common.AbstractWindowsCommand):
    """Recover TrueCrypt 7.1a Master Keys"""
    
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                        help = 'Directory in which to dump the keys')
        config.add_option('VERSION', short_option = 'T', default = '7.1a', 
                        help = 'Truecrypt version string (default: 7.1a)')

        self.version_map = {
            # the most recent - released feb 2012
            '7.1a' : {'32bit': tc_71a_vtypes_x86, '64bit': tc_71a_vtypes_x64}, 
            # released july 2010. also supports 6.3a from 
            # november 2009, so its likely all versions between
            # 6.3a and 7.0a are supported by these vtypes
            '7.0a' : {'32bit': tc_70a_vtypes_x86, '64bit': tc_70a_vtypes_x64}, 
            }

    def apply_types(self, addr_space):
        """Apply the TrueCrypt types for a specific version of TC. 

        @param addr_space: <volatility.BaseAddressSpace>
        """

        mm_model = addr_space.profile.metadata.get('memory_model', '32bit')
        try:
            vtypes = self.version_map[self._config.VERSION][mm_model]
            addr_space.profile.vtypes.update(vtypes)
            addr_space.profile.merge_overlay({
            'EXTENSION' : [ None, {
                'wszVolume' : [ None, ['String', dict(length = 260, encoding = "utf16")]],
            }], 
            'CRYPTO_INFO_t' : [ None, { 
                'mode' : [ None, ['Enumeration', dict(target = "long", 
                            choices = {1: 'XTS', 
                                       2: 'LWR', 
                                       3: 'CBC', 
                                       4: 'OUTER_CBC', 
                                       5: 'INNER_CBC'})]],
                'ea' : [ None, ['Enumeration', dict(target = "long", 
                            choices = {1: 'AES', 
                                       2: 'SERPENT', 
                                       3: 'TWOFISH', 
                                       4: 'BLOWFISH', 
                                       5: 'CAST', 
                                       6: 'TRIPLEDES'})]],
            }]})
            addr_space.profile.compile()
        except KeyError:
            ver = self._config.VERSION
            debug.error("Truecrypt version {0} is not supported".format(ver))

    def calculate(self):
        addr_space = utils.load_as(self._config)
        self.apply_types(addr_space)
        scanner = filescan.DriverScan(self._config)
        for driver in scanner.calculate():    
            drivername = str(driver.DriverName or '')
            if drivername.endswith("truecrypt"):
                for device in driver.devices():
                    code = device.DeviceType.v()
                    type = devicetree.DEVICE_CODES.get(code)
                    if type == 'FILE_DEVICE_DISK':
                        yield device
        
    def render_text(self, outfd, data):
        for device in data:
            ext = device.DeviceExtension.dereference_as("EXTENSION")
            outfd.write("Container: {0}\n".format(ext.wszVolume))
            outfd.write("Hidden Volume: {0}\n".format("Yes" if ext.cryptoInfo.hiddenVolume == 1 else "No"))
            outfd.write("Removable: {0}\n".format("Yes" if ext.bRemovable == 1 else "No"))
            outfd.write("Read Only: {0}\n".format("Yes" if ext.bReadOnly == 1 else "No"))
            outfd.write("Disk Length: {0} (bytes)\n".format(ext.DiskLength))
            outfd.write("Host Length: {0} (bytes)\n".format(ext.HostLength))
            outfd.write("Encryption Algorithm: {0}\n".format(ext.cryptoInfo.ea))
            outfd.write("Mode: {0}\n".format(ext.cryptoInfo.mode))
            outfd.write("Master Key\n")
            key = device.obj_vm.read(ext.cryptoInfo.master_keydata.obj_offset, 64)
            addr = ext.cryptoInfo.master_keydata.obj_offset
            outfd.write("{0}\n".format("\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(addr + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(key)
                    ])))
            if self._config.DUMP_DIR:
                if not os.path.isdir(self._config.DUMP_DIR):
                    debug.error("The path {0} is not a valid directory".format(self._config.DUMP_DIR))
                name = "{0:#x}_master.key".format(addr)
                keyfile = os.path.join(self._config.DUMP_DIR, name)
                with open(keyfile, "wb") as handle:
                    handle.write(key)
                outfd.write("Dumped {0} bytes to {1}\n".format(len(key), keyfile))
            outfd.write("\n")