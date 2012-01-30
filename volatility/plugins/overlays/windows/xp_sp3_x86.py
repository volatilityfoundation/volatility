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
import ssdt_vtypes
import pe_vtypes
import copy
import volatility.debug as debug #pylint: disable-msg=W0611

overlay = copy.deepcopy(xp_sp2_x86.overlay)

vtypes = copy.deepcopy(xp_sp3_x86_vtypes.nt_types)

vtypes.update(crash_vtypes.crash_vtypes)
vtypes.update(kdbg_vtypes.kdbg_vtypes)
vtypes.update(hibernate_vtypes.hibernate_vtypes)
vtypes.update(tcpip_vtypes.tcpip_vtypes)
vtypes.update(ssdt_vtypes.ssdt_vtypes)
vtypes.update(pe_vtypes.pe_vtypes)

class WinXPSP3x86(windows.AbstractWindowsX86):
    """ A Profile for Windows XP SP3 x86 """
    _md_major = 5
    _md_minor = 1
    overlay = overlay
    abstract_types = vtypes
    syscalls = xp_sp2_x86_syscalls.syscalls
