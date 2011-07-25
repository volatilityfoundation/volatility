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
import volatility.debug as debug #pylint: disable-msg=W0611

win2k3sp1x86overlays = copy.deepcopy(win2k3_sp0_x86.win2k3sp0x86overlays)

win2k3sp1x86overlays['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x1e\x00")]
win2k3sp1x86overlays['VOLATILITY_MAGIC'][1]['HiveListPoolSize'][1] = ['VolatilityMagic', dict(value = 0x588)]
win2k3sp1x86overlays['_ETHREAD'][1]['CreateTime'][1] = ['WinTimeStamp', {}]

win2k3_sp1_x86_vtypes.ntoskrnl_types.update(crash_vtypes.crash_vtypes)
win2k3_sp1_x86_vtypes.ntoskrnl_types.update(hibernate_vtypes.hibernate_vtypes)
win2k3_sp1_x86_vtypes.ntoskrnl_types.update(tcpip_vtypes.tcpip_vtypes)
win2k3_sp1_x86_vtypes.ntoskrnl_types.update(tcpip_vtypes.tcpip_vtypes_2k3_sp1_sp2)
win2k3_sp1_x86_vtypes.ntoskrnl_types.update(kdbg_vtypes.kdbg_vtypes)

class Win2K3SP1x86(windows.AbstractWindows):
    """ A Profile for Windows 2003 SP1 x86 """
    _md_major = 5
    _md_minor = 2
    abstract_types = win2k3_sp1_x86_vtypes.ntoskrnl_types
    overlay = win2k3sp1x86overlays
    object_classes = copy.deepcopy(win2k3_sp0_x86.Win2K3SP0x86.object_classes)
    syscalls = win2k3_sp12_x86_syscalls.syscalls

