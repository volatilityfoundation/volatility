# Volatility
# Copyright (c) 2008-2011 Volatile Systems
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
@author:       Bradley L Schatz
@license:      GNU General Public License 2.0 or later
@contact:      bradley@schatzforensic.com.au

This file provides support for windows Windows 7 SP 0.
"""

#pylint: disable-msg=C0111

import copy
import win7_sp0_x86_vtypes
import win7_sp0_x86_syscalls
import vista_sp0_x86
import windows
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import tcpip_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

win7sp0x86overlays = copy.deepcopy(vista_sp0_x86.vistasp0x86overlays)

win7sp0x86overlays['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x26\x00")]
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['KPCR'][1] = ['VolatilityKPCR', dict(configname = 'KPCR')]
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['KDBGHeader'][1] = ['VolatilityMagic', dict(value = '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x40\x03')]
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['HiveListOffset'][1] = ['VolatilityMagic', dict(value = 0x30c)]
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['HiveListPoolSize'][1] = ['VolatilityMagic', dict(value = 0x638)]

# Add a new member to the VOLATILIY_MAGIC type
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['ObjectPreamble'] = [ 0x0, ['VolatilityMagic', dict(value = '_OBJECT_HEADER_CREATOR_INFO')]]

win7sp0x86overlays['VOLATILITY_MAGIC'][1]['InfoMaskToOffset'] = [ 0x0, ['VolatilityMagic', \
      dict(value = { 0x1 : 0x10, 0x2 : 0x10, 0x3 : 0x20, \
                      0x4 : 0x8, 0x5 : 0x18, 0x6 : 0x20, \
                      0x7 : 0x28, 0x8 : 0x10, 0x9 : 0x20, \
                      0xa : 0x20, 0xb : 0x30, 0xc : 0x18, \
                      0xd : 0x28, 0xe : 0x28, 0xf : 0x38, \
                      0x10: 0x8, 0x11: 0x18, 0x12: 0x18, \
                      0x13: 0x28, 0x14: 0x10, 0x15: 0x20, \
                      0x16: 0x20, 0x17: 0x30, 0x18: 0x18, \
                      0x19: 0x28, 0x1A: 0x28, 0x1b: 0x38, \
                      0x1c: 0x20, 0x1d: 0x30, 0x1e: 0x30, \
                      0x1f: 0x40 })]]

win7sp0x86overlays['VOLATILITY_MAGIC'][1]['InfoMaskMap'] = [ 0x0, ['VolatilityMagic', \
      dict(value = { '_OBJECT_HEADER_CREATOR_INFO' : 0x01, \
                      '_OBJECT_HEADER_NAME_INFO' : 0x02, \
                      '_OBJECT_HEADER_HANDLE_INFO' : 0x04, \
                      '_OBJECT_HEADER_QUOTA_INFO' : 0x08, \
                      '_OBJECT_HEADER_PROCESS_INFO': 0x10 })]]

win7sp0x86overlays['VOLATILITY_MAGIC'][1]['TypeIndexMap'] = [ 0x0, ['VolatilityMagic', \
      dict(value = { 'Type' : 0x2, \
                    'Directory' : 0x3, \
                    'SymbolicLink' : 0x4, \
                    'Token' : 0x5, \
                    'Job' : 0x6, \
                    'Process' : 0x7, \
                    'Thread' : 0x8, \
                    'UserApcReserve' : 0x9, \
                    'IoCompletionReserve' : 0xa, \
                    'DebugObject' : 0xb, \
                    'Event' : 0xc, \
                    'EventPair' : 0xd, \
                    'Mutant' : 0xe, \
                    'Callback' : 0xf, \
                    'Semaphore' : 0x10, \
                    'Timer' : 0x11, \
                    'Profile' : 0x12, \
                    'KeyedEvent' : 0x13, \
                    'WindowStation' : 0x14, \
                    'Desktop' : 0x15, \
                    'TpWorkerFactory' : 0x16, \
                    'Adapter' : 0x17, \
                    'Controller' : 0x18, \
                    'Device' : 0x19, \
                    'Driver' : 0x1a, \
                    'IoCompletion' : 0x1b, \
                    'File' : 0x1c, \
                    'TmTm' : 0x1d, \
                    'TmTx' : 0x1e, \
                    'TmRm' : 0x1f, \
                    'TmEn' : 0x20, \
                    'Section' : 0x21, \
                    'Session' : 0x22, \
                    'Key' : 0x23, \
                    'ALPC Port' : 0x24, \
                    'PowerRequest' : 0x25, \
                    'WmiGuid' : 0x26, \
                    'EtwRegistration' : 0x27, \
                    'EtwConsumer' : 0x28, \
                    'FilterConnectionPort' : 0x29, \
                    'FilterCommunicationPort' : 0x2a, \
                    'PcwObject' : 0x2b })]]

win7_sp0_x86_vtypes.nt_types.update(crash_vtypes.crash_vtypes)
win7_sp0_x86_vtypes.nt_types.update(hibernate_vtypes.hibernate_vtypes)
win7_sp0_x86_vtypes.nt_types.update(kdbg_vtypes.kdbg_vtypes)
win7_sp0_x86_vtypes.nt_types.update(tcpip_vtypes.tcpip_vtypes)
win7_sp0_x86_vtypes.nt_types.update(tcpip_vtypes.tcpip_vtypes_vista)
win7_sp0_x86_vtypes.nt_types.update(tcpip_vtypes.tcpip_vtypes_7)

win7_sp0_x86_vtypes.nt_types.update({\
  '_OBJECT_HEADER_NAME_INFORMATION' : [ 0xc, {
  'Directory' : [ 0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
  'Name' : [ 0x04, ['_UNICODE_STRING']],
} ], \
})

class Win7SP0x86(windows.AbstractWindowsX86):
    """ A Profile for Windows 7 SP0 x86 """
    _md_major = 6
    _md_minor = 1
    abstract_types = win7_sp0_x86_vtypes.nt_types
    overlay = win7sp0x86overlays
    object_classes = copy.deepcopy(vista_sp0_x86.VistaSP0x86.object_classes)
    syscalls = win7_sp0_x86_syscalls.syscalls
    # FIXME: Temporary fix for issue 105
    native_types = copy.deepcopy(windows.AbstractWindowsX86.native_types)
    native_types['pointer64'] = windows.AbstractWindowsX86.native_types['unsigned long long']
