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

import sys
import volatility.debug as debug
import volatility.obj as obj

# SSDT structures for all x86 profiles *except* Win 2003 Server
ssdt_vtypes = {
    '_SERVICE_DESCRIPTOR_TABLE' : [ 0x40, {
    'Descriptors' : [0x0, ['array', 4, ['_SERVICE_DESCRIPTOR_ENTRY']]],
    }],
    '_SERVICE_DESCRIPTOR_ENTRY' : [ 0x10, {
    'KiServiceTable' : [0x0, ['pointer', ['void']]],
    'CounterBaseTable' : [0x4, ['pointer', ['unsigned long']]],
    'ServiceLimit' : [0x8, ['unsigned long']],
    'ArgumentTable' : [0xc, ['pointer', ['unsigned char']]],
    }],
}

# SSDT structures for Win 2003 Server x86
ssdt_vtypes_2003 = {
    '_SERVICE_DESCRIPTOR_TABLE' : [ 0x20, {
    'Descriptors' : [0x0, ['array', 2, ['_SERVICE_DESCRIPTOR_ENTRY']]],
    }],
}

# SSDT structures for x64
ssdt_vtypes_64 = {
    '_SERVICE_DESCRIPTOR_TABLE' : [ 0x40, {
    'Descriptors' : [0x0, ['array', 2, ['_SERVICE_DESCRIPTOR_ENTRY']]],
    }],
    '_SERVICE_DESCRIPTOR_ENTRY' : [ 0x20, {
    'KiServiceTable' : [0x0, ['pointer64', ['void']]],
    'CounterBaseTable' : [0x8, ['pointer64', ['unsigned long']]],
    'ServiceLimit' : [0x10, ['unsigned long long']],
    'ArgumentTable' : [0x18, ['pointer64', ['unsigned char']]],
    }],
}

#### Filthy Hack for backwards compatibility

def syscalls_property(x):
    debug.debug("Deprecation warning: Please use profile.additional['syscalls'] over profile.syscalls")
    return x.additional.get('syscalls', [[], []])

class WinSyscallsAttribute(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):
        # Filthy hack for backwards compatibilitiy
        profile.__class__.syscalls = property(syscalls_property)

####

class AbstractSyscalls(obj.ProfileModification):
    syscall_module = 'No default'
    def modification(self, profile):
        module = sys.modules.get(self.syscall_module, None)
        profile.additional['syscalls'] = module.syscalls

class WinXPSyscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.xp_sp2_x86_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 5,
                  'minor': lambda x : x == 1}

class Win64SyscallVTypes(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(ssdt_vtypes_64)

class Win2003SyscallVTypes(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}
    def modification(self, profile):
        profile.vtypes.update(ssdt_vtypes_2003)

class Win2003SP0Syscalls(AbstractSyscalls):
    # Win2003SP12Syscalls applies to SP0 as well, so this must be applied second
    before = ['Win2003SP12Syscalls']
    syscall_module = 'volatility.plugins.overlays.windows.win2003_sp0_x86_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2,
                  'build': lambda x: x == 3789}

class Win2003SP12Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.win2003_sp12_x86_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 5,
                  'minor': lambda x : x == 2}

class Win2003SP12x64Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.win2003_sp12_x64_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 5,
                  'minor': lambda x : x == 2}

class VistaSP0Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.vista_sp0_x86_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 0,
                  'build': lambda x : x == 6000}

class VistaSP0x64Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.vista_sp0_x64_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 0,
                  'build': lambda x : x == 6000}

class VistaSP12Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.vista_sp12_x86_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 0,
                  'build': lambda x : x >= 6001}

class VistaSP12x64Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.vista_sp12_x64_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 0,
                  'build': lambda x : x >= 6001}

class Win7SP01Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.win7_sp01_x86_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 1}

class Win7SP01x64Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.win7_sp01_x64_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 1}

class Win8SP0x64Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.win8_sp0_x64_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 2}

class Win8SP0x86Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.win8_sp0_x86_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 2}

class Win8SP1x86Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.win8_sp1_x86_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 3}

class Win8SP1x64Syscalls(AbstractSyscalls):
    syscall_module = 'volatility.plugins.overlays.windows.win8_sp1_x64_syscalls'
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 3}