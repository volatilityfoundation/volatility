# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
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
import volatility.plugins.gui.vtypes.win7_sp0_x64_vtypes_gui as win7_sp0_x64_vtypes_gui
import volatility.plugins.gui.constants as consts

class Vista2008x64GuiVTypes(obj.ProfileModification):

    before = ["XP2003x64BaseVTypes", "Win32Kx64VTypes"]

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0}

    def modification(self, profile):
        # Enough stayed the same between Vista/2008 and Windows 7, 
        ## so we can re-use the Windows 7 types. This is a bit unconventional
        ## because we typically when we re-use, we do it forward (i.e. use 
        ## an older OS's types for a newer OS). However since the win32k.sys
        ## vtypes were never public until Windows 7, we're re-using backward.
        profile.vtypes.update(win7_sp0_x64_vtypes_gui.win32k_types)

        # We don't want to overlay or HeEntrySize from Win7 will
        # appear to be a valid member of the Vista structure.
        profile.vtypes.update({
            'tagSHAREDINFO' : [ 0x238, {
            'psi' : [ 0x0, ['pointer64', ['tagSERVERINFO']]],
            'aheList' : [ 0x8, ['pointer64', ['_HANDLEENTRY']]],
            'ulSharedDelta' : [ 0x18, ['unsigned long long']],
            }],
        })

        profile.merge_overlay({
            # From Win7SP0x64
            'tagDESKTOP' : [ None, {
            'pheapDesktop' : [ 0x78, ['pointer64', ['tagWIN32HEAP']]],
            'ulHeapSize' : [ 0x80, ['unsigned long']],
            }],
            'tagTHREADINFO' : [ None, {
            'ppi' : [ 0x68, ['pointer64', ['tagPROCESSINFO']]],
            'PtiLink' : [ 0x160, ['_LIST_ENTRY']],
            }],
            'tagHOOK': [ None, {
            'flags': [ None, ['Flags', {'bitmap': consts.HOOK_FLAGS}]]
            }],
            '_HANDLEENTRY': [ None, {
            'bType': [ None, ['Enumeration', dict(target = 'unsigned char', choices = consts.HANDLE_TYPE_ENUM)]],
            }],
            'tagWINDOWSTATION' : [ None, {
            'pClipBase' : [ None, ['pointer', ['array', lambda x : x.cNumClipFormats, ['tagCLIP']]]],
            }],
            'tagCLIP': [ None, {
            'fmt' : [ 0x0, ['Enumeration', dict(target = 'unsigned long', choices = consts.CLIPBOARD_FORMAT_ENUM)]],
            }],
        })

class Vista2008x86GuiVTypes(obj.ProfileModification):

    before = ["XP2003x86BaseVTypes", "Win32Kx86VTypes"]

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0}

    def modification(self, profile):

        profile.merge_overlay({
            # The size is very important since we carve from bottom up
            'tagWINDOWSTATION' : [ 0x54, {
            'pClipBase' : [ None, ['pointer', ['array', lambda x : x.cNumClipFormats, ['tagCLIP']]]],
            }],
            'tagDESKTOP' : [ None, {
            'PtiList' : [ 0x64, ['_LIST_ENTRY']],
            'hsectionDesktop' : [ 0x3c, ['pointer', ['void']]],
            'pheapDesktop' : [ 0x40, ['pointer', ['tagWIN32HEAP']]],
            'ulHeapSize' : [ 0x44, ['unsigned long']],
            }],
            'tagTHREADINFO' : [ None, { # same as win2003x86
            'PtiLink' : [ 0xB0, ['_LIST_ENTRY']],
            'fsHooks' : [ 0x9C, ['unsigned long']],
            'aphkStart' : [ 0xF8, ['array', 16, ['pointer', ['tagHOOK']]]],
            }],
            'tagSERVERINFO' : [ None, {
            'cHandleEntries' : [ 0x4, ['unsigned long']],
            'cbHandleTable' : [ 0x1c8, ['unsigned long']],
            }],
            'tagSHAREDINFO' : [ 0x11c, { # From Win7SP0x86
            'psi' : [ 0x0, ['pointer', ['tagSERVERINFO']]],
            'aheList' : [ 0x4, ['pointer', ['_HANDLEENTRY']]],
            'ulSharedDelta' : [ 0xC, ['unsigned long']],
            }],
            'tagCLIP' : [ 16, { # just a size change
            }]})
