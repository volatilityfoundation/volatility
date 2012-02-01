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
import win7_sp01_x86_syscalls
import vista_sp0_x86
import windows
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import tcpip_vtypes
import ssdt_vtypes
import pe_vtypes
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611

overlay = copy.deepcopy(vista_sp0_x86.overlay)

object_classes = copy.deepcopy(vista_sp0_x86.object_classes)

native_types = copy.deepcopy(windows.AbstractWindowsX86.native_types)

vtypes = copy.deepcopy(win7_sp0_x86_vtypes.nt_types)

overlay['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x26\x00")]
overlay['VOLATILITY_MAGIC'][1]['KDBGHeader'][1] = ['VolatilityMagic', dict(value = '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x40\x03')]

vtypes.update(crash_vtypes.crash_vtypes)
vtypes.update(hibernate_vtypes.hibernate_vtypes)
vtypes.update(kdbg_vtypes.kdbg_vtypes)
vtypes.update(tcpip_vtypes.tcpip_vtypes_vista)
vtypes.update(tcpip_vtypes.tcpip_vtypes_7)
vtypes.update(ssdt_vtypes.ssdt_vtypes)
vtypes.update(pe_vtypes.pe_vtypes)

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
                o = obj.NoneObject("Header not set")

            self.newattr(name, o)

    def get_object_type(self):
        """Return the object's type as a string"""
        return self.type_map.get(self.TypeIndex.v(), '')

# Update the win7 implementation
object_classes["_OBJECT_HEADER"] = _OBJECT_HEADER

native_types['pointer64'] = windows.AbstractWindowsX86.native_types['unsigned long long']

class Win7SP0x86(windows.AbstractWindowsX86):
    """ A Profile for Windows 7 SP0 x86 """
    _md_major = 6
    _md_minor = 1
    overlay = overlay
    abstract_types = vtypes
    object_classes = object_classes
    syscalls = win7_sp01_x86_syscalls.syscalls
    # FIXME: Temporary fix for issue 105
    native_types = native_types
