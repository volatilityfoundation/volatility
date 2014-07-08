# Volatility
# Copyright (C) 2007-2014 Volatility Foundation
# Copyright (C) 2014 Michael Hale Ligh <michael.ligh@mnin.org>
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
import volatility.plugins.gui.vtypes.win7_sp0_x86_vtypes_gui as win7_sp0_x86_vtypes_gui
import volatility.plugins.gui.vtypes.win7_sp0_x64_vtypes_gui as win7_sp0_x64_vtypes_gui

class _RTL_ATOM_TABLE_ENTRY(win32k_core._RTL_ATOM_TABLE_ENTRY):
    """A class for atom table entries"""

    @property
    def Flags(self):
        return self.Reference.Flags

    @property
    def ReferenceCount(self):
        return self.Reference.ReferenceCount

class Win8x86Gui(obj.ProfileModification):

    before = ["XP2003x86BaseVTypes", "Win32Kx86VTypes", "AtomTablex86Overlay", "Win32KCoreClasses"]

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x > 1}

    def modification(self, profile):

        profile.vtypes.update(win7_sp0_x86_vtypes_gui.win32k_types)
        profile.object_classes.update({'_RTL_ATOM_TABLE_ENTRY': _RTL_ATOM_TABLE_ENTRY})

        profile.merge_overlay({
            'tagWINDOWSTATION' : [ None, {
            ## ForceEmptyClipboard
            ## lea     eax, [esi+28h]
            ## call    @HMAssignmentUnlock@4 ; HMAssignmentUnlock(x)
            ## lea     eax, [esi+24h]
            ## call    @HMAssignmentUnlock@4 ; HMAssignmentUnlock(x)
            'spwndClipOwner': [0x28, ['pointer', ['tagWND']]],
            'spwndClipViewer': [0x24, ['pointer', ['tagWND']]],

            ## _EnumClipboardFormats
            ## mov     ecx, [esi+30h]
            'pClipBase' : [ 0x30, ['pointer', ['array', lambda x : x.cNumClipFormats, ['tagCLIP']]]], 

            ## xxxEmptyClipboard
            ## mov     eax, [ebx+34h]
            'cNumClipFormats': [0x34, ['unsigned long']],

            ## xxxEmptyClipboard
            ## call    @HMAssignmentLock@8 ; HMAssignmentLock(x,x)
            ## inc     dword ptr [ebx+38h]
            'iClipSerialNumber': [0x38, ['unsigned long']],

            ## xxxCreateWindowStation
            ## lea     edi, [edi+48h]
            ## call    _CreateGlobalAtomTab
            'pGlobalAtomTable': [ 0x48, ['pointer', ['void']]],
            }],

            '_HANDLEENTRY': [ None, {
            'bType': [ None, ['Enumeration', dict(target = 'unsigned char', choices = consts.HANDLE_TYPE_ENUM_SEVEN)]],
            }],

            'tagCLIP': [ 20, {
            'fmt' : [ None, ['Enumeration', dict(target = 'unsigned long', choices = consts.CLIPBOARD_FORMAT_ENUM)]],
            }],

            'tagTHREADINFO': [ None, {
            ## xxxCreateWindowStation
            ## mov     ebx, _gptiCurrent
            ## mov     eax, [ebx+0C4h]
            'ppi': [0xc4, ['pointer', ['tagPROCESSINFO']]],

            ## zzzReattachThreads
            ## lea     ebx, [edi-158h]
            ## mov     ecx, [ebx+130h]
            'PtiLink': [0x158, ['_LIST_ENTRY']],
            }],

            'tagDESKTOP': [ None, {
            ## ParseDesktop
            ## mov     edi, [edi+8]
            ## test    edi, edi
            'rpdeskNext': [8, ['pointer', ['tagDESKTOP']]],

            ## DestroyDesktop
            ## mov     ebx, [ebp+arg_0]
            ## mov     eax, [ebx+0Ch]
            'rpwinstaParent': [0xc, ['pointer', ['tagWINDOWSTATION']]],

            ## DesktopAlloc
            ## mov     eax, [eax+3Ch]
            ## push    edi
            ## push    [ebp+Size]      ; Size
            'pheapDesktop': [0x3c, ['pointer', ['tagWIN32HEAP']]],

            ### xxxCreateDesktopEx2
            ## add     eax, 58h
            ## mov     [eax+4], eax
            ## mov     [eax], eax    
            'PtiList': [0x58, ['_LIST_ENTRY']],
            }],

            '_RTL_ATOM_TABLE': [ None, {
            'NumBuckets': [ 0x14, ['unsigned long']],
            'Buckets': [ 0x18, ['array', lambda x : x.NumBuckets,
                ['pointer', ['_RTL_ATOM_TABLE_ENTRY']]]],
            }],

        })

class Win8x64Gui(obj.ProfileModification):

    before = ["Win32KCoreClasses"]

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x > 1}

    def modification(self, profile):

        profile.vtypes.update(win7_sp0_x64_vtypes_gui.win32k_types)
        profile.object_classes.update({'_RTL_ATOM_TABLE_ENTRY': _RTL_ATOM_TABLE_ENTRY})

        profile.merge_overlay({

            'tagWINDOWSTATION': [ None, { 
            ## _EnumClipboardFormats
            ## mov     rcx, [rdi+60h]
            ## test    rcx, rcx
            'pClipBase' : [ 0x60, ['pointer', ['array', lambda x : x.cNumClipFormats, ['tagCLIP']]]], 

            ## xxxEmptyClipboard
            ## mov     ebp, [rbx+68h]
            'cNumClipFormats': [0x68, ['unsigned long']],

            ## xxxEmptyClipboard
            ## call    HMAssignmentLock
            ## inc     dword ptr [rbx+6Ch]
            'iClipSerialNumber': [0x6c, ['unsigned long']],

            ## xxxCreateWindowStation
            ## add     rcx, 88h
            ## call    CreateGlobalAtomTable 
            'pGlobalAtomTable': [ 0x88, ['pointer', ['void']]],
            }],

            'tagDESKTOP': [ None, {
            ## ParseDesktop
            ## mov     rdi, [rdi+10h]
            'rpdeskNext': [0x10, ['pointer', ['tagDESKTOP']]],

            ## DestroyDesktop
            ## mov     eax, [rcx+20h]
            ## mov     rdi, [rcx+18h]
            'rpwinstaParent': [0x18, ['pointer', ['tagWINDOWSTATION']]],

            ## DesktopAlloc
            ## mov     rcx, [rcx+78h]
            ## mov     r8d, edx
            ## xor     edx, edx
            'pheapDesktop': [0x78, ['pointer', ['tagWIN32HEAP']]],

            ### xxxCreateDesktopEx2
            ## add     rax, 0A0h
            ## mov     [rax+8], rax 
            'PtiList': [0xA0, ['_LIST_ENTRY']],
            }],

            'tagTHREADINFO': [ None, {
            ## xxxCreateWindowStation
            ## mov     rsi, cs:gptiCurrent
            ## mov     rax, [r14+10h]
            ## mov     rcx, [rax+170h]
            'ppi': [0x170, ['pointer', ['tagPROCESSINFO']]],

            ## zzzReattachThreads
            ## lea     rsi, [rdi-280h]
            ## mov     rdx, [rsi+230h] ; struct tagQ *
            ## cmp     rdx, [rsi+178h]
            'PtiLink': [0x280, ['_LIST_ENTRY']],
            }],

            'tagCLIP': [ None, {
            'fmt' : [ None, ['Enumeration', dict(target = 'unsigned long', choices = consts.CLIPBOARD_FORMAT_ENUM)]],
            }],

            '_RTL_ATOM_TABLE': [ None, {
            'NumBuckets': [ 0x1C, ['unsigned long']],
            'Buckets': [ 0x20, ['array', lambda x : x.NumBuckets,
                ['pointer', ['_RTL_ATOM_TABLE_ENTRY']]]],
            }],

            '_HANDLEENTRY': [ None, {
            'bType': [ None, ['Enumeration', dict(target = 'unsigned char', choices = consts.HANDLE_TYPE_ENUM_SEVEN)]],
            }],

            })