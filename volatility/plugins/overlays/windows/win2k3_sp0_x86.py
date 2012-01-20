# Volatility
# Copyright (c) 2008 Volatile Systems
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
@author:       Jamie Levy (Gleeda)
@license:      GNU General Public License 2.0 or later
@contact:      jamie.levy@gmail.com

This file provides support for Windows 2003 SP0. 
"""

#pylint: disable-msg=C0111

import copy
import win2k3_sp0_x86_vtypes
import win2k3_sp0_x86_syscalls
import xp_sp2_x86
import windows
import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.obj as obj

win2k3sp0x86overlays = copy.deepcopy(xp_sp2_x86.xpsp2overlays)

win2k3sp0x86overlays['_EPROCESS'][1]['VadRoot'][1] = ['_MM_AVL_TABLE']

win2k3sp0x86overlays['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x1B\x00")]
win2k3sp0x86overlays['VOLATILITY_MAGIC'][1]['KPCR'][1] = ['VolatilityKPCR', dict(value = 0xffdff000, configname = 'KPCR')]
win2k3sp0x86overlays['VOLATILITY_MAGIC'][1]['KDBGHeader'][1] = ['VolatilityMagic', dict(value = '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x18\x03')]

win2k3_sp0_x86_vtypes.nt_types.update(crash_vtypes.crash_vtypes)
win2k3_sp0_x86_vtypes.nt_types.update(hibernate_vtypes.hibernate_vtypes)
win2k3_sp0_x86_vtypes.nt_types.update(tcpip_vtypes.tcpip_vtypes)
win2k3_sp0_x86_vtypes.nt_types.update(tcpip_vtypes.tcpip_vtypes_vista)
win2k3_sp0_x86_vtypes.nt_types.update(kdbg_vtypes.kdbg_vtypes)

class Win2K3SP0x86(windows.AbstractWindowsX86):
    """ A Profile for Windows 2003 SP0 x86 """
    _md_major = 5
    _md_minor = 2
    abstract_types = win2k3_sp0_x86_vtypes.nt_types
    overlay = win2k3sp0x86overlays
    object_classes = windows.AbstractWindowsX86.object_classes.copy()
    syscalls = win2k3_sp0_x86_syscalls.syscalls

class _MM_AVL_TABLE(obj.CType):
    def traverse(self):
        """
        This is a hack to get around the fact that _MM_AVL_TABLE.BalancedRoot (an _MMADDRESS_NODE) doesn't
        work the same way as the other _MMADDRESS_NODEs. In particular, we want _MMADDRESS_NODE to behave
        like _MMVAD, and all other _MMADDRESS_NODEs have a Vad, VadS, Vadl tag etc, but _MM_AVL_TABLE.BalancedRoot
        does not. So we can't reference self.BalancedRoot.RightChild here because self.BalancedRoot will be None
        due to the fact that there is not a valid VAD tag at self.BalancedRoot.obj_offset - 4 (as _MMVAD expects).

        We want to start traversing from self.BalancedRoot.RightChild. The self.BalancedRoot.LeftChild member
        will always be 0. However, we can't call get_obj_offset("_MMADDRESS_NODE", "RightChild") or it will 
        result in a TypeError: __new__() takes exactly 5 non-keyword arguments (4 given). Therefore, we hard-code
        the offset to the RightChild and treat it as a pointer to the first real _MMADDRESS_NODE. 

        Update: hard-coding the offset to RightChild breaks x64 (since the offset is 8 on x86 and 16 on x64). 
        Thus to fix the vad plugins for x64 we assume that the offset of RightChild in _MMVAD_SHORT is the 
        same as the offset of RightChild in _MMADDRESS_NODE. We can call get_obj_offset on _MMVAD_SHORT since
        it isn't in the _MMVAD factory like _MMADDRESS_NODE; and we won't get the above TypeError. 
        """
        right_child_offset = self.obj_vm.profile.get_obj_offset("_MMVAD_SHORT", "RightChild")

        rc = obj.Object("Pointer", vm = self.obj_vm, offset = self.obj_offset + right_child_offset)

        node = obj.Object('_MMADDRESS_NODE', vm = self.obj_vm, offset = rc.v(), parent = self.obj_parent)

        for c in node.traverse():
            yield c

class _MMVAD_SHORT(windows._MMVAD_SHORT):
    def get_parent(self):
        return self.u1.Parent

    def get_control_area(self):
        return self.ControlArea

    def get_file_object(self):
        return self.ControlArea.FilePointer

class _MMVAD_LONG(_MMVAD_SHORT):
    pass

Win2K3SP0x86.object_classes['_MM_AVL_TABLE'] = _MM_AVL_TABLE
Win2K3SP0x86.object_classes['_MMADDRESS_NODE'] = windows._MMVAD
Win2K3SP0x86.object_classes['_MMVAD_SHORT'] = _MMVAD_SHORT
Win2K3SP0x86.object_classes['_MMVAD_LONG'] = _MMVAD_LONG
