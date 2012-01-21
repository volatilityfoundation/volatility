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

This file provides support for Windows 2k8/Vista SP 1. We provide a profile
for SP1.
"""

#pylint: disable-msg=C0111

import copy
import vista_sp0_x64
import vista_sp1_x64_vtypes
import vista_sp12_x86_syscalls
import windows64
import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

overlay = copy.deepcopy(vista_sp0_x64.overlay)

object_classes = copy.deepcopy(vista_sp0_x64.object_classes)

vtypes = copy.deepcopy(vista_sp1_x64_vtypes.ntkrnlmp_types)

overlay['VOLATILITY_MAGIC'][1]['KDBGHeader'][1] = ['VolatilityMagic', dict(value = '\x00\xf8\xff\xffKDBG\x30\x03')]

vtypes.update(crash_vtypes.crash_vtypes)
vtypes.update(hibernate_vtypes.hibernate_vtypes)
#vtypes.update(hibernate_vtypes.hibernate_vistasp2_x64_vtypes)
vtypes.update(kdbg_vtypes.kdbg_vtypes)
vtypes.update(tcpip_vtypes.tcpip_vtypes_vista)

class VistaSP1x64(windows64.AbstractWindowsX64):
    """ A Profile for Windows Vista SP1 x64 """
    _md_major = 6
    _md_minor = 0
    abstract_types = vista_sp1_x64_vtypes.ntkrnlmp_types
    overlay = overlay
    object_classes = object_classes
    syscalls = vista_sp12_x86_syscalls.syscalls

class Win2K8SP1x64(VistaSP1x64):
    """ A Profile for Windows 2008 SP1 x64 """
