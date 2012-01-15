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

This file provides support for Windows 2008 SP1.
"""

#pylint: disable-msg=C0111

import copy
import win2k8_sp1_x86_vtypes
import vista_sp1_x86
import vista_sp12_x86_syscalls
import windows
import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

win2k8sp1x86overlays = copy.deepcopy(vista_sp1_x86.vistasp1x86overlays)

win2k8_sp1_x86_vtypes.nt_types.update(crash_vtypes.crash_vtypes)
win2k8_sp1_x86_vtypes.nt_types.update(hibernate_vtypes.hibernate_vtypes)
win2k8_sp1_x86_vtypes.nt_types.update(kdbg_vtypes.kdbg_vtypes)
win2k8_sp1_x86_vtypes.nt_types.update(tcpip_vtypes.tcpip_vtypes)
win2k8_sp1_x86_vtypes.nt_types.update(tcpip_vtypes.tcpip_vtypes_vista)

class Win2K8SP1x86(windows.AbstractWindowsX86):
    """ A Profile for Windows 2008 SP1 x86 """
    _md_major = 6
    _md_minor = 0
    abstract_types = win2k8_sp1_x86_vtypes.nt_types
    overlay = win2k8sp1x86overlays
    object_classes = copy.deepcopy(vista_sp1_x86.VistaSP1x86.object_classes)
    syscalls = vista_sp12_x86_syscalls.syscalls

