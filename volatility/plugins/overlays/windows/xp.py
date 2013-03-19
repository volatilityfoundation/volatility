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
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu

This file provides support for Windows XP.
"""

#pylint: disable-msg=C0111

import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.obj as obj

class XPOverlay(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 1}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x1b\x00")]],
                        'KDBGHeader'   : [ None, ['VolatilityMagic', dict(value = '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x90\x02')]],
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x2)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0xff)]],
                                                }],
                   '_EPROCESS'        : [ None, {
                        'VadRoot'      : [ None, ['pointer', ['_MMVAD']]]
                                                }]
                      }
        profile.merge_overlay(overlay)

class WinXPSP2x86(obj.Profile):
    """ A Profile for Windows XP SP2 x86 """
    _md_major = 5
    _md_minor = 1
    _md_os = 'windows'
    _md_memory_model = '32bit'
    _md_vtype_module = 'volatility.plugins.overlays.windows.xp_sp2_x86_vtypes'

class WinXPSP3x86(obj.Profile):
    """ A Profile for Windows XP SP3 x86 """
    _md_major = 5
    _md_minor = 1
    _md_os = 'windows'
    _md_memory_model = '32bit'
    _md_vtype_module = 'volatility.plugins.overlays.windows.xp_sp3_x86_vtypes'


