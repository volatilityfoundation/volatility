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
import volatility.plugins.gui.constants as consts
import volatility.plugins.gui.win32k_core as win32k_core
import volatility.plugins.gui.vtypes.win7_sp0_x64_vtypes_gui as win7_sp0_x64_vtypes_gui
import volatility.plugins.gui.vtypes.win7_sp0_x86_vtypes_gui as win7_sp0_x86_vtypes_gui
import volatility.plugins.gui.vtypes.win7_sp1_x64_vtypes_gui as win7_sp1_x64_vtypes_gui
import volatility.plugins.gui.vtypes.win7_sp1_x86_vtypes_gui as win7_sp1_x86_vtypes_gui

class Win7SP0x64GuiVTypes(obj.ProfileModification):
    """Apply the base vtypes for Windows 7 SP0 x64"""

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'build': lambda x : x == 7600}

    def modification(self, profile):
        profile.vtypes.update(win7_sp0_x64_vtypes_gui.win32k_types)

class Win7SP1x64GuiVTypes(obj.ProfileModification):
    """Apply the base vtypes for Windows 7 SP1 x64"""

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'build': lambda x : x == 7601}

    def modification(self, profile):
        profile.vtypes.update(win7_sp1_x64_vtypes_gui.win32k_types)

class Win7SP0x86GuiVTypes(obj.ProfileModification):
    """Apply the base vtypes for Windows 7 SP0 x86"""

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'build': lambda x : x == 7600}

    def modification(self, profile):
        profile.vtypes.update(win7_sp0_x86_vtypes_gui.win32k_types)

class Win7SP1x86GuiVTypes(obj.ProfileModification):
    """Apply the base vtypes for Windows 7 SP1 x86"""

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'build': lambda x : x == 7601}

    def modification(self, profile):
        profile.vtypes.update(win7_sp1_x86_vtypes_gui.win32k_types)

class Win7GuiOverlay(obj.ProfileModification):
    """Apply general overlays for Windows 7"""

    before = ['Win7SP0x64GuiVTypes', 'Win7SP1x64GuiVTypes',
              'Win7SP0x86GuiVTypes', 'Win7SP1x86GuiVTypes']

    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1}

    def modification(self, profile):
        profile.merge_overlay({
            'tagHOOK': [ None, {
            'flags': [ None, ['Flags', {'bitmap': consts.HOOK_FLAGS}]]
            }],
            '_HANDLEENTRY': [ None, {
            'bType': [ None, ['Enumeration', dict(target = 'unsigned char', choices = consts.HANDLE_TYPE_ENUM_SEVEN)]],
            }],
            'tagWINDOWSTATION' : [ None, {
            'pClipBase' : [ None, ['pointer', ['array', lambda x : x.cNumClipFormats, ['tagCLIP']]]],
            }],
            'tagCLIP': [ None, {
            'fmt' : [ None, ['Enumeration', dict(target = 'unsigned long', choices = consts.CLIPBOARD_FORMAT_ENUM)]],
            }]})

class Win7Vista2008x64Timers(obj.ProfileModification):
    """Apply the tagTIMER for Windows 7, Vista, and 2008 x64"""

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x >= 6}

    def modification(self, profile):
        # http://doxygen.reactos.org/d5/dd0/timer_8h_source.html#l00019
        profile.vtypes.update({
            'tagTIMER' : [ None, {
            'head' : [ 0x00, ['_HEAD']],
            'ListEntry' : [ 0x18, ['_LIST_ENTRY']],
            'spwnd' : [ 0x28, ['pointer', ['tagWND']]],
            'pti' : [ 0x30, ['pointer', ['tagTHREADINFO']]],
            'nID' : [ 0x38, ['unsigned short']],
            'cmsCountdown' : [ 0x40, ['unsigned int']],
            'cmsRate' : [ 0x44, ['unsigned int']],
            'flags' : [ 0x48, ['Flags', {'bitmap': consts.TIMER_FLAGS}]],
            'pfn' : [ 0x50, ['pointer', ['void']]],
            }]})

class Win7Vista2008x86Timers(obj.ProfileModification):
    """Apply the tagTIMER for Windows 7, Vista, and 2008 x86"""

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x >= 6}

    def modification(self, profile):
        profile.vtypes.update({
            'tagTIMER' : [ None, {
            'ListEntry' : [ 0xc, ['_LIST_ENTRY']],
            'pti' : [ 0x18, ['pointer', ['tagTHREADINFO']]],
            'spwnd' : [ 0x14, ['pointer', ['tagWND']]], #??
            'nID' : [ 0x1C, ['unsigned short']],
            'cmsCountdown' : [ 0x20, ['unsigned int']],
            'cmsRate' : [ 0x24, ['unsigned int']],
            'flags' : [ 0x28, ['Flags', {'bitmap': consts.TIMER_FLAGS}]],
            'pfn' : [ 0x2C, ['pointer', ['void']]],
            }]})

class _MM_SESSION_SPACE(win32k_core._MM_SESSION_SPACE): #pylint: disable-msg=W0212
    """A class for session spaces on Windows 7"""

    def find_shared_info(self):
        """The way we find win32k!gSharedInfo on Windows 7
        is different than before. For each DWORD in the 
        win32k.sys module's .data section (DWORD-aligned)
        we check if its the HeEntrySize member of a possible
        tagSHAREDINFO structure. This should equal the size 
        of a _HANDLEENTRY.

        The HeEntrySize member didn't exist before Windows 7
        thus the need for separate methods."""

        handle_table_size = self.obj_vm.profile.\
                            get_obj_size("_HANDLEENTRY")

        handle_entry_offset = self.obj_vm.profile.\
                            get_obj_offset("tagSHAREDINFO", "HeEntrySize")

        for chunk in self._section_chunks(".data"):

            if chunk != handle_table_size:
                continue

            shared_info = obj.Object("tagSHAREDINFO",
                offset = chunk.obj_offset - handle_entry_offset,
                vm = self.obj_vm)

            if shared_info.is_valid():
                return shared_info

        return obj.NoneObject("Cannot find win32k!gSharedInfo")

class tagSHAREDINFO(win32k_core.tagSHAREDINFO):
    """A class for shared info blocks on Windows 7"""

    def is_valid(self):
        """Sanity checks for tagSHAREDINFO"""

        if not obj.CType.is_valid(self):
            return False

        if self.ulSharedDelta != 0:
            return False

        if not self.psi.is_valid():
            return False

        return self.psi.cbHandleTable / self.HeEntrySize == self.psi.cHandleEntries

class Win7Win32KCoreClasses(obj.ProfileModification):
    """Apply the core object classes for Windows 7"""

    before = ["WindowsObjectClasses", "Win32KCoreClasses"]

    conditions = {'os': lambda x: x == 'windows',
                  'major' : lambda x : x == 6,
                  'minor' : lambda x : x == 1}

    def modification(self, profile):

        profile.object_classes.update({
            '_MM_SESSION_SPACE': _MM_SESSION_SPACE,
            'tagSHAREDINFO': tagSHAREDINFO,
            })

