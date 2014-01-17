# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import volatility.obj as obj

class Win2003x86GuiVTypes(obj.ProfileModification):
    """Apply the overlays for Windows 2003 x86 (builds on Windows XP x86)"""

    before = ["XP2003x86BaseVTypes"]

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}

    def modification(self, profile):

        profile.merge_overlay({
            'tagWINDOWSTATION' : [ 0x54, {
            'spwndClipOwner' : [ 0x18, ['pointer', ['tagWND']]],
            'pGlobalAtomTable' : [ 0x3C, ['pointer', ['void']]],
            }],
            'tagTHREADINFO' : [ None, {
            'PtiLink' : [ 0xB0, ['_LIST_ENTRY']],
            'fsHooks' : [ 0x9C, ['unsigned long']],
            'aphkStart' : [ 0xF8, ['array', 16, ['pointer', ['tagHOOK']]]],
            }],
            'tagDESKTOP' : [ None, {
            'hsectionDesktop' : [ 0x3c, ['pointer', ['void']]],
            'pheapDesktop' : [ 0x40, ['pointer', ['tagWIN32HEAP']]],
            'ulHeapSize' : [ 0x44, ['unsigned long']],
            'PtiList' : [ 0x60, ['_LIST_ENTRY']],
            }],
            'tagSERVERINFO' : [ None, {
            'cHandleEntries' : [ 4, ['unsigned long']],
            'cbHandleTable' : [ 0x1b8, ['unsigned long']],
            }],
        })

