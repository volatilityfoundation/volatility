# Volatility
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

This file provides support for windows XP SP3. We provide a profile
for SP3.
"""

#pylint: disable-msg=C0111

import copy
import vista_sp0_x86_vtypes
import vista_sp0_x86_syscalls
import win2k3_sp2_x86
import windows
import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

vistasp0x86overlays = copy.deepcopy(win2k3_sp2_x86.win2k3sp2x86overlays)

vistasp0x86overlays['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x20\x00")]
vistasp0x86overlays['VOLATILITY_MAGIC'][1]['KPCR'][1] = ['VolatilityKPCR', dict(configname = 'KPCR')]
vistasp0x86overlays['VOLATILITY_MAGIC'][1]['KDBGHeader'][1] = ['VolatilityMagic', dict(value = '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x28\x03')]
vistasp0x86overlays['VOLATILITY_MAGIC'][1]['HiveListOffset'][1] = ['VolatilityMagic', dict(value = 0x308)]
vistasp0x86overlays['VOLATILITY_MAGIC'][1]['HiveListPoolSize'][1] = ['VolatilityMagic', dict(value = 0x5d8)]

vista_sp0_x86_vtypes.nt_types.update(crash_vtypes.crash_vtypes)
vista_sp0_x86_vtypes.nt_types.update(hibernate_vtypes.hibernate_vtypes)
vista_sp0_x86_vtypes.nt_types.update(kdbg_vtypes.kdbg_vtypes)
vista_sp0_x86_vtypes.nt_types.update(tcpip_vtypes.tcpip_vtypes)
vista_sp0_x86_vtypes.nt_types.update(tcpip_vtypes.tcpip_vtypes_vista)

class VistaSP0x86(windows.AbstractWindowsX86):
    """ A Profile for Windows Vista SP0 x86 """
    _md_major = 6
    _md_minor = 0
    abstract_types = vista_sp0_x86_vtypes.nt_types
    overlay = vistasp0x86overlays
    object_classes = copy.deepcopy(win2k3_sp2_x86.Win2K3SP2x86.object_classes)
    syscalls = vista_sp0_x86_syscalls.syscalls

class _MMVAD_SHORT(windows._MMVAD_SHORT):
    def get_parent(self):
        return self.u1.Parent

    def get_control_area(self):
        return self.Subsection.ControlArea

    def get_file_object(self):
        return self.Subsection.ControlArea.FilePointer.dereference_as("_FILE_OBJECT")

class _MMVAD_LONG(_MMVAD_SHORT):
    pass

VistaSP0x86.object_classes['_MMVAD_SHORT'] = _MMVAD_SHORT
VistaSP0x86.object_classes['_MMVAD_LONG'] = _MMVAD_LONG
