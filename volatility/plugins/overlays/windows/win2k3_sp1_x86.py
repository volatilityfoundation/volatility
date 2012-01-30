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

This file provides support for Windows 2003 SP1. 
"""

#pylint: disable-msg=C0111

import copy
import win2k3_sp1_x86_vtypes
import win2k3_sp12_x86_syscalls
import win2k3_sp0_x86
import windows
import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import ssdt_vtypes
import pe_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

overlay = copy.deepcopy(win2k3_sp0_x86.overlay)

object_classes = copy.deepcopy(win2k3_sp0_x86.object_classes)

vtypes = copy.deepcopy(win2k3_sp1_x86_vtypes.nt_types)

# Starting with Windows 2003 SP1 _ETHREAD.CreateTime is a WinTimeStamp, not a ThreadCreateTimeStamp
overlay['_ETHREAD'][1]['CreateTime'][1] = ['WinTimeStamp', {}]
overlay['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x1e\x00")]

vtypes.update(crash_vtypes.crash_vtypes)
vtypes.update(hibernate_vtypes.hibernate_vtypes)
vtypes.update(tcpip_vtypes.tcpip_vtypes)
vtypes.update(tcpip_vtypes.tcpip_vtypes_2k3_sp1_sp2)
vtypes.update(kdbg_vtypes.kdbg_vtypes)
vtypes.update(ssdt_vtypes.ssdt_vtypes)
vtypes.update(ssdt_vtypes.ssdt_vtypes_2k3)
vtypes.update(pe_vtypes.pe_vtypes)

class Win2K3SP1x86(windows.AbstractWindowsX86):
    """ A Profile for Windows 2003 SP1 x86 """
    _md_major = 5
    _md_minor = 2
    overlay = overlay
    abstract_types = vtypes
    object_classes = object_classes
    syscalls = win2k3_sp12_x86_syscalls.syscalls

