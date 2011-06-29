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


import xp_sp3_x86_vtypes
import xp_sp2_x86_syscalls
import xp_sp2_x86
import windows
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import tcpip_vtypes
import copy
import volatility.debug as debug #pylint: disable-msg=W0611

xpsp3overlays = copy.deepcopy(xp_sp2_x86.xpsp2overlays)

xpsp3overlays['_MMVAD_SHORT'][1]['Flags'][0] = lambda x: x.u.obj_offset
xpsp3overlays['_CONTROL_AREA'][1]['Flags'][0] = lambda x: x.u.obj_offset
xpsp3overlays['_MMVAD_LONG'][1]['Flags'][0] = lambda x: x.u.obj_offset
xpsp3overlays['_MMVAD_LONG'][1]['Flags2'][0] = lambda x: x.u2.obj_offset

xp_sp3_x86_vtypes.ntoskrnl_types.update(crash_vtypes.crash_vtypes)
xp_sp3_x86_vtypes.ntoskrnl_types.update(kdbg_vtypes.kdbg_vtypes)
xp_sp3_x86_vtypes.ntoskrnl_types.update(hibernate_vtypes.hibernate_vtypes)
xp_sp3_x86_vtypes.ntoskrnl_types.update(tcpip_vtypes.tcpip_vtypes)

class WinXPSP3x86(windows.AbstractWindows):
    """ A Profile for windows XP SP3 """
    _md_major = 5
    _md_minor = 1
    abstract_types = xp_sp3_x86_vtypes.ntoskrnl_types
    overlay = xpsp3overlays
    syscalls = xp_sp2_x86_syscalls.syscalls
