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

This file provides support for Windows 2003 SP2.
"""

#pylint: disable-msg=C0111

import copy
import win2k3_sp12_x64_syscalls
import win2k3_sp2_x64_vtypes
import win2k3_sp1_x64
import windows64
# import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import ssdt_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

overlay = copy.deepcopy(win2k3_sp1_x64.overlay)

object_classes = copy.deepcopy(win2k3_sp1_x64.object_classes)

vtypes = copy.deepcopy(win2k3_sp2_x64_vtypes.ntkrnlmp_types)

vtypes.update(crash_vtypes.crash_vtypes)
vtypes.update(hibernate_vtypes.hibernate_vtypes)
### TODO: Create 64-bit types for tcpip.sys
# win2k3_sp2_x64_vtypes.ntkrnlmp_types.update(tcpip_vtypes.tcpip_vtypes)
# win2k3_sp2_x64_vtypes.ntkrnlmp_types.update(tcpip_vtypes.tcpip_vtypes_2k3_sp1_sp2)
vtypes.update(kdbg_vtypes.kdbg_vtypes)
vtypes.update(ssdt_vtypes.ssdt_vtypes_64)

# Alias _IMAGE_NT_HEADERS for 64-bit systems
vtypes["_IMAGE_NT_HEADERS"] = vtypes["_IMAGE_NT_HEADERS64"]

class Win2K3SP2x64(windows64.AbstractWindowsX64):
    """ A Profile for Windows 2003 SP2 x64 """
    _md_major = 5
    _md_minor = 2
    overlay = overlay
    abstract_types = vtypes
    object_classes = object_classes
    syscalls = win2k3_sp12_x64_syscalls.syscalls

class WinXPSP2x64(Win2K3SP2x64):
    """ A Profile for Windows XP SP2 x64 """
