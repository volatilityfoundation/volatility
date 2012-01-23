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
@author:       Michael Cohen
@license:      GNU General Public License 2.0 or later
@contact:      scudette@gmail.com

This file provides support for Windows 7 SP 0 64 bit version. Many thanks to
Alex Pease (alex.pease@gmail.com) for his assistance.
"""

#pylint: disable-msg=C0111

import copy
import vista_sp2_x64
import win7_sp0_x86
import win7_sp0_x64_vtypes
import win7_sp0_x86_syscalls
import windows64
import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

overlay = copy.deepcopy(vista_sp2_x64.overlay)

object_classes = copy.deepcopy(vista_sp2_x64.object_classes)

vtypes = copy.deepcopy(win7_sp0_x64_vtypes.ntkrnlmp_types)

overlay['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x58\x00")]
overlay['VOLATILITY_MAGIC'][1]['KDBGHeader'][1] = ['VolatilityMagic', dict(value = '\x00\xf8\xff\xffKDBG\x40\x03')]

overlay['_KTHREAD'] = [ None, {'ServiceTable' : lambda x: x.Spare0 }]

vtypes.update(crash_vtypes.crash_vtypes)
vtypes.update(hibernate_vtypes.hibernate_vtypes)
#vtypes.update(hibernate_vtypes.hibernate_win7_vtypes)
#vtypes.update(hibernate_vtypes.hibernate_win7_x64_vtypes)
vtypes.update(kdbg_vtypes.kdbg_vtypes)
# Apply tcpip_vtypes_vista only for _IN_ADDR 
vtypes.update(tcpip_vtypes.tcpip_vtypes_vista)
vtypes.update(tcpip_vtypes.tcpip_vtypes_7_64)

# Alias _IMAGE_NT_HEADERS for 64-bit systems
vtypes["_IMAGE_NT_HEADERS"] = vtypes["_IMAGE_NT_HEADERS64"]

object_classes["_OBJECT_HEADER"] = win7_sp0_x86._OBJECT_HEADER

class Win7SP0x64(windows64.AbstractWindowsX64):
    """ A Profile for Windows 7 SP0 x64 """
    _md_major = 6
    _md_minor = 1
    overlay = overlay
    abstract_types = vtypes
    object_classes = object_classes
    syscalls = win7_sp0_x86_syscalls.syscalls
