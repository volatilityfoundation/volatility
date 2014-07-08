# Volatility
# Copyright (C) 2008-2012 Volatile Systems
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie@memoryanalysis.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0 or later
@contact:      jamie@memoryanalysis.net
@organization: Volatile Systems
"""

import volatility.plugins.registry.registryapi as registryapi
import volatility.debug as debug
import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.addrspace as addrspace


# Windows XP types taken from RegRipper auditpol plugin
auditpol_type_xp = {
    'AuditPolDataXP' : [ None, {
        'Enabled' : [ 0x0, ['unsigned char']],
        'System' : [ 0x4, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Logons' : [0x8, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Files' : [0xc, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'UserRights': [0x10, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Process': [0x14, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'PolicyChange': [0x18, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AccountManagement': [0x1c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DirectoryAccess': [0x20, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AccountLogon': [0x24, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
    } ],
}

# Vista and Windows 7 structures taken from http://www.kazamiya.net/files/PolAdtEv_Structure_en_rev2.pdf
auditpol_type_vista = {
    'AuditPolDataVista' : [ None, {
        # System
        'SecurityState' : [ 0xc, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SecuritySystem' : [ 0xe, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SystemIntegrity' : [0x10, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'IPSecDriver': [0x12, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SystemOther': [0x14, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Logon/Logoff
        'Logon': [0x16, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Logoff': [0x18, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AccountLockout': [0x1a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'IPSecMainMode': [0x1c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SpecialLogon': [0x1e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'IPSecQuickMode': [0x20, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'IPSecExtended': [0x22, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'LogonOther': [0x24, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'NetworkPolicyServer': [0x26, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # File Object
        'FileSystem': [0x28, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Registry': [0x2a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'KernelObject': [0x2c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SAM': [0x2e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'ObjectOther': [0x30, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Certification': [0x32, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Application': [0x34, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'HandleManipulation': [0x36, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'FileShare': [0x38, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'PacketDrop': [0x3a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'PlatformConnection': [0x3c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Privelege Use
        'Sensitive': [0x3e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'NonSensitive': [0x40, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'PrivilegeOther': [0x42, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        #Detailed Tracking
        'ProcessCreation': [0x44, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'ProcessTermination': [0x46, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DPAPI': [0x48, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'RPC': [0x4a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Policy Change
        'AuditPolicyChange': [0x4c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AuthenticationPolicyChange': [0x4e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AuthorizationPolicyChange': [0x50, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'MPSSVCRule': [0x52, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'FilteringPlatformPolicyChange': [0x54, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'PolicyOther': [0x56, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Account Management
        'UserAccount': [0x58, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'ComputerAccount': [0x5a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SecurityGroup': [0x5c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DistributionGroup': [0x5e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'ApplicationGroup': [0x60, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AccountOther': [0x62, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # DS ACcess
        'DirectoryServiceAccess': [0x64, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DirectoryServiceChange': [0x66, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DirectoryServiceReplication': [0x68, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DetailedDirServReplication': [0x6a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Account Logon
        'CredentialValidation': [0x6c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'KerberosOperations': [0x6e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AccountLogonOther': [0x70, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'KerberosAuthentication': [0x72, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
    } ],
}

auditpol_type_win7 = {
    'AuditPolData7' : [ None, {
        # System
        'SecurityState' : [ 0xc, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SecuritySystem' : [ 0xe, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SystemIntegrity' : [0x10, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'IPSecDriver': [0x12, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SystemOther': [0x14, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Logon/Logoff
        'Logon': [0x16, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Logoff': [0x18, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AccountLockout': [0x1a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'IPSecMainMode': [0x1c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SpecialLogon': [0x1e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'IPSecQuickMode': [0x20, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'IPSecExtended': [0x22, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'LogonOther': [0x24, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'NetworkPolicyServer': [0x26, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # File Object
        'FileSystem': [0x28, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Registry': [0x2a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'KernelObject': [0x2c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SAM': [0x2e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'ObjectOther': [0x30, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Certification': [0x32, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'Application': [0x34, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'HandleManipulation': [0x36, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'FileShare': [0x38, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'PacketDrop': [0x3a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'PlatformConnection': [0x3c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DetailedFileShare': [0x3e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Privelege Use
        'Sensitive': [0x40, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'NonSensitive': [0x42, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'PrivilegeOther': [0x44, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        #Detailed Tracking
        'ProcessCreation': [0x46, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'ProcessTermination': [0x48, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DPAPI': [0x4a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'RPC': [0x4c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Policy Change
        'AuditPolicyChange': [0x4e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AuthenticationPolicyChange': [0x50, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AuthorizationPolicyChange': [0x52, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'MPSSVCRule': [0x54, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'FilteringPlatformPolicyChange': [0x56, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'PolicyOther': [0x58, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Account Management
        'UserAccount': [0x5a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'ComputerAccount': [0x5c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'SecurityGroup': [0x5e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DistributionGroup': [0x60, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'ApplicationGroup': [0x62, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AccountOther': [0x64, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # DS ACcess
        'DirectoryServiceAccess': [0x66, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DirectoryServiceChange': [0x68, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DirectoryServiceReplication': [0x6a, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'DetailedDirServReplication': [0x6c, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        # Account Logon
        'CredentialValidation': [0x6e, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'KerberosOperations': [0x70, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'AccountLogonOther': [0x72, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
        'KerberosAuthentication': [0x74, ['Enumeration', dict(target = 'unsigned short', choices = {0x00: "Not Logged", 0x01: "S", 0x02: "F", 0x03: "S/F"})]],
    } ],
}

class AuditPolDataXP(obj.CType):
    def __str__(self):
        audit = "Disabled"
        if int(self.Enabled) != 0:
            audit = "Enabled" 
        msg = "Auditing is {0}\n\tAudit System Events: {1}\n\tAudit Logon Events: {2}\n\tAudit Object Access: {3}\n\t".format(
                    audit, self.System, self.Logons, self.Files)
        msg += "Audit Privilege Use: {0}\n\tAudit Process Tracking: {1}\n\tAudit Policy Change: {2}\n\tAudit Account Management: {3}\n\t".format(
                    self.UserRights, self.Process, self.PolicyChange, self.AccountManagement)
        msg += "Audit Dir Service Access: {0}\n\tAudit Account Logon Events: {1}\n".format(self.DirectoryAccess, self.AccountLogon)
        return msg 

class AuditPolDataVista(obj.CType):
    def __str__(self):
        msg = "System Events:\n\tSecurity State Change: {0}\n\tSecurity System Extention: {1}\n\tSystem Integrity: {2}\n\t".format(
                    self.SecurityState, self.SecuritySystem, self.SystemIntegrity)
        msg += "IPSec Driver: {0}\n\tOther System Events: {1}\n".format(
                    self.IPSecDriver, self.SystemOther)
        msg += "Logon/Logoff Events:\n\tLogon: {0}\n\tLogoff: {1}\n\tAccount Lockout: {2}\n\t".format(
                    self.Logon, self.Logoff, self.AccountLockout)
        msg += "IPSec Main Mode: {0}\n\tSpecial Logon: {1}\n\tIPSec Quick Mode: {2}\n\tIPSec Extended Mode: {3}\n\t".format(
                    self.IPSecMainMode, self.SpecialLogon, self.IPSecQuickMode, self.IPSecExtended)
        msg += "Other Logon Events: {0}\n\tNetwork Policy Server: {1}\n".format(
                    self.LogonOther, self.NetworkPolicyServer)
        msg += "Object Access Events:\n\tFile System: {0}\n\tRegistry: {1}\n\tKernel Object: {2}\n\t".format(
                    self.FileSystem, self.Registry, self.KernelObject)
        msg += "SAM: {0}\n\tOther Object Events: {1}\n\tCertification Services: {2}\n\tApplication Generated: {3}\n\t".format(
                    self.SAM, self.ObjectOther, self.Certification, self.Application)
        msg += "Handle Manipulation: {0}\n\tFile Share: {1}\n\tFiltering Platform Packet Drop: {2}\n\t".format(
                    self.HandleManipulation, self.FileShare, self.PacketDrop)
        msg += "Filtering Platform Connection: {0}\nPrivelege Use:\n\t".format(
                    self.PlatformConnection) 
        msg += "Sensitive: {0}\n\tNon Sensitive{1}\n\tOther Privilege Use Events{2}\nDetailed Tracking:\n\t".format(
                    self.Sensitive, self.NonSensitive, self.PrivilegeOther)
        msg += "Process Creation: {0}\n\tProcess Termination: {1}\n\tDPAPI Activity: {2}\n\tRPC Events\n".format(
                    self.ProcessCreation, self.ProcessTermination, self.DPAPI, self.RPC)
        msg += "Policy Change Events:\n\tAudit Policy Change: {0}\n\tAuthentication Policy Change: {1}\n\t".format(
                    self.AuditPolicyChange, self.AuthenticationPolicyChange)
        msg += "Authorization Policy Change: {0}\n\tMPSSVC Rule: {1}\n\tFiltering Platform Policy Change: {2}\n\t".format(
                    self.AuthorizationPolicyChange, self.MPSSVCRule, self.FilteringPlatformPolicyChange)
        msg += "Other Policy Events: {0}\nAccount Management Events:\n\tUser Account Management: {1}\n\t".format(
                    self.PolicyOther, self.UserAccount)
        msg += "Computer Account Management: {0}\n\tSecurity Group Management: {1}\n\tDistribution Group Management: {2}\n\t".format(
                    self.ComputerAccount, self.SecurityGroup, self.DistributionGroup)
        msg += "Application Group Management: {0}\n\tOther Account Management Events: {1}\nDS Access Events:\n\t".format(
                    self.ApplicationGroup, self.AccountOther)
        msg += "Directory Service Access: {0}\n\tDirectory Service Changes: {1}\n\tDirectory Service Replication: {2}\n\t".format(
                    self.DirectoryServiceAccess, self.DirectoryServiceChange, self.DirectoryServiceReplication)
        msg += "Detailed Directory Service Replication: {0}\nAccount Logon Events:\n\tCredential Validation: {1}\n\t".format(
                    self.DetailedDirServReplication, self.CredentialValidation)
        msg += "Kerberos Service Ticket Operations: {0}\n\tOther Account Logon Events: {1}\n\tKerberos Authentication Service: {2}\n".format(
                    self.KerberosOperations, self.AccountLogonOther, self.KerberosAuthentication)

        return msg


class AuditPolData7(obj.CType):
    def __str__(self):
        msg = "System Events:\n\tSecurity State Change: {0}\n\tSecurity System Extention: {1}\n\tSystem Integrity: {2}\n\t".format(
                    self.SecurityState, self.SecuritySystem, self.SystemIntegrity)
        msg += "IPSec Driver: {0}\n\tOther System Events: {1}\n".format(
                    self.IPSecDriver, self.SystemOther)
        msg += "Logon/Logoff Events:\n\tLogon: {0}\n\tLogoff: {1}\n\tAccount Lockout: {2}\n\t".format(
                    self.Logon, self.Logoff, self.AccountLockout)
        msg += "IPSec Main Mode: {0}\n\tSpecial Logon: {1}\n\tIPSec Quick Mode: {2}\n\tIPSec Extended Mode: {3}\n\t".format(
                    self.IPSecMainMode, self.SpecialLogon, self.IPSecQuickMode, self.IPSecExtended)
        msg += "Other Logon Events: {0}\n\tNetwork Policy Server: {1}\n".format(
                    self.LogonOther, self.NetworkPolicyServer)
        msg += "Object Access Events:\n\tFile System: {0}\n\tRegistry: {1}\n\tKernel Object: {2}\n\t".format(
                    self.FileSystem, self.Registry, self.KernelObject)
        msg += "SAM: {0}\n\tOther Object Events: {1}\n\tCertification Services: {2}\n\tApplication Generated: {3}\n\t".format(
                    self.SAM, self.ObjectOther, self.Certification, self.Application)
        msg += "Handle Manipulation: {0}\n\tFile Share: {1}\n\tFiltering Platform Packet Drop: {2}\n\t".format(
                    self.HandleManipulation, self.FileShare, self.PacketDrop)
        msg += "Filtering Platform Connection: {0}\n\tDetailed File Share: {1}\nPrivelege Use:\n\t".format(
                    self.PlatformConnection, self.DetailedFileShare)
        msg += "Sensitive: {0}\n\tNon Sensitive{1}\n\tOther Privilege Use Events{2}\nDetailed Tracking:\n\t".format(
                    self.Sensitive, self.NonSensitive, self.PrivilegeOther)
        msg += "Process Creation: {0}\n\tProcess Termination: {1}\n\tDPAPI Activity: {2}\n\tRPC Events\n".format(
                    self.ProcessCreation, self.ProcessTermination, self.DPAPI, self.RPC)
        msg += "Policy Change Events:\n\tAudit Policy Change: {0}\n\tAuthentication Policy Change: {1}\n\t".format(
                    self.AuditPolicyChange, self.AuthenticationPolicyChange)
        msg += "Authorization Policy Change: {0}\n\tMPSSVC Rule: {1}\n\tFiltering Platform Policy Change: {2}\n\t".format(
                    self.AuthorizationPolicyChange, self.MPSSVCRule, self.FilteringPlatformPolicyChange)
        msg += "Other Policy Events: {0}\nAccount Management Events:\n\tUser Account Management: {1}\n\t".format(
                    self.PolicyOther, self.UserAccount)
        msg += "Computer Account Management: {0}\n\tSecurity Group Management: {1}\n\tDistribution Group Management: {2}\n\t".format(
                    self.ComputerAccount, self.SecurityGroup, self.DistributionGroup)
        msg += "Application Group Management: {0}\n\tOther Account Management Events: {1}\nDS Access Events:\n\t".format(
                    self.ApplicationGroup, self.AccountOther)
        msg += "Directory Service Access: {0}\n\tDirectory Service Changes: {1}\n\tDirectory Service Replication: {2}\n\t".format(
                    self.DirectoryServiceAccess, self.DirectoryServiceChange, self.DirectoryServiceReplication)
        msg += "Detailed Directory Service Replication: {0}\nAccount Logon Events:\n\tCredential Validation: {1}\n\t".format(
                    self.DetailedDirServReplication, self.CredentialValidation)
        msg += "Kerberos Service Ticket Operations: {0}\n\tOther Account Logon Events: {1}\n\tKerberos Authentication Service: {2}\n".format(
                    self.KerberosOperations, self.AccountLogonOther, self.KerberosAuthentication)

        return msg 

class AuditpolTypesXP(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x <= 1}
    def modification(self, profile):
        profile.object_classes.update({
            'AuditPolDataXP': AuditPolDataXP,
        })
        profile.vtypes.update(auditpol_type_xp)


class AuditpolTypesVista(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0}
    def modification(self, profile):
        profile.object_classes.update({
            'AuditPolDataVista': AuditPolDataVista,
        })
        profile.vtypes.update(auditpol_type_vista)

class AudipolWin7(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1}
    def modification(self, profile):
        profile.object_classes.update({
            'AuditPolData7': AuditPolData7,
        })
        profile.vtypes.update(auditpol_type_win7)


class Auditpol(common.AbstractWindowsCommand):
    """Prints out the Audit Policies from HKLM\\SECURITY\\Policy\\PolAdtEv"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('HEX', short_option = 'H', default = False,
                          help = 'Output HEX of Policy\\PolAdtEv key',
                          action = "store_true")

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'unknown').lower() == 'windows'

    def calculate(self):
        addr_space = utils.load_as(self._config)
        regapi = registryapi.RegistryApi(self._config)
        regapi.reset_current()

        version = (addr_space.profile.metadata.get('major', 0),
                   addr_space.profile.metadata.get('minor', 0))
        for value, data_raw in regapi.reg_yield_values('security', 'Policy\\PolAdtEv', thetype = 'REG_NONE'):
            bufferas = addrspace.BufferAddressSpace(self._config, data = data_raw)
            if version <= (5, 1):
                ap = obj.Object("AuditPolDataXP", offset = 0, vm = bufferas)
            elif version <= (6, 0):
                ap = obj.Object("AuditPolDataVista", offset = 0, vm = bufferas)
            else:
                ap = obj.Object("AuditPolData7", offset = 0, vm = bufferas)
            if ap == None:
                debug.error("No AuditPol data found")

            yield data_raw, ap

    def render_text(self, outfd, data):
        for data_raw, ap in data:
            if self._config.HEX:
                raw = "\n".join(["{0:010x}: {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(data_raw)])
                outfd.write(raw + "\n\n")
            outfd.write("{0}\n".format(str(ap)))
