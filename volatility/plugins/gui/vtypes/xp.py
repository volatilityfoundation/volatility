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

class XP2003x86BaseVTypes(obj.ProfileModification):
    """Applies to everything x86 before Windows 7"""

    def check(self, profile):
        m = profile.metadata
        version = (m.get('major', 0), m.get('minor', 0))

        return (m.get('os', None) == 'windows' and
                    version < (6, 1) and
                    m.get('memory_model', '32bit') == '32bit')

    def modification(self, profile):

        profile.vtypes.update({
            'tagWINDOWSTATION' : [ 0x5C, {
            'dwSessionId' : [ 0x0, ['unsigned long']],
            'rpwinstaNext' : [ 0x4, ['pointer', ['tagWINDOWSTATION']]],
            'rpdeskList' : [ 0x8, ['pointer', ['tagDESKTOP']]],
            'dwWSF_Flags' : [ 0x10, ['unsigned long']],
            'ptiDrawingClipboard' : [ 0x1C, ['pointer', ['tagTHREADINFO']]],
            'spwndClipOpen' : [ 0x20, ['pointer', ['tagWND']]],
            'spwndClipViewer' : [ 0x24, ['pointer', ['tagWND']]],
            'spwndClipOwner' : [ 0x28, ['pointer', ['tagWND']]],
            'pClipBase' : [ 0x2C, ['pointer', ['array', lambda x : x.cNumClipFormats, ['tagCLIP']]]],
            'cNumClipFormats' : [ 0x30, ['unsigned int']],
            'iClipSerialNumber' : [ 0x34, ['unsigned int']],
            'iClipSequenceNumber' : [ 0x38, ['unsigned int']],
            #'spwndClipboardListener' : [ 0x3C, ['pointer', ['tagWND']]], 
            'pGlobalAtomTable' : [ 0x40, ['pointer', ['void']]],
            }],
            ## This is defined in Windows 7
            'tagCLIP' : [ 12, {
            'fmt' : [ 0, ['Enumeration', dict(target = 'unsigned long', choices = consts.CLIPBOARD_FORMAT_ENUM)]],
            'hData' : [ 4, ['unsigned int']],
            'fGlobalHandle' : [ 8, ['unsigned int']],
            }],
            'tagDESKTOP' : [ 0x84, {
            'dwSessionId' : [ 0x0, ['unsigned long']],
            'pDeskInfo' : [ 0x4, ['pointer', ['tagDESKTOPINFO']]],
            'rpdeskNext' : [ 0xc, ['pointer', ['tagDESKTOP']]],
            'rpwinstaParent' : [ 0x10, ['pointer', ['tagWINDOWSTATION']]],
            'hsectionDesktop' : [ 0x40, ['pointer', ['void']]],
            'pheapDesktop' : [ 0x44, ['pointer', ['tagWIN32HEAP']]],
            'PtiList' : [ 0x64, ['_LIST_ENTRY']],
            }],
            'tagTHREADINFO' : [ None, { # Same as Win32Thread
            'pEThread' : [ 0x00, ['pointer', ['_ETHREAD']]],
            'ppi' : [ 0x2C, ['pointer', ['tagPROCESSINFO']]],
            'pq' : [ 0x30, ['pointer', ['tagQ']]],
            'pDeskInfo' : [ 0x40, ['pointer', ['tagDESKTOPINFO']]],
            'PtiLink' : [ 0xAC, ['_LIST_ENTRY']],
            'fsHooks' : [ 0x98, ['unsigned long']],
            'aphkStart' : [ 0xF4, ['array', 16, ['pointer', ['tagHOOK']]]],
            }],
            'tagQ' : [ None, {
            'mlInput' : [ 0x00, ['tagMLIST']],
            }],
            'tagMLIST' : [ None, {
            'pqmsgRead' : [ 0x00, ['pointer', ['tagQMSG']]],
            'cMsgs' : [ 0x08, ['unsigned long']],
            }],
            'tagQMSG' : [ None, {
            'pqmsgNext' : [ 0x00, ['pointer', ['tagQMSG']]],
            'pqmsgPrev' : [ 0x04, ['pointer', ['tagQMSG']]],
            'msg' : [ 0x08, ['tagMSG']],
            }],
            'tagMSG' : [ None, {
            'hwnd' : [ 0x00, ['unsigned long']],
            'message' : [ 0x04, ['unsigned long']],
            'wParam' : [ 0x08, ['unsigned long']],
            'lParam' : [ 0x0C, ['unsigned long']],
            'time' : [ 0x10, ['unsigned long']],
            'pt' : [ 0x14, ['tagPOINT']],
            }],
            'tagPOINT' : [ None, {
            'x' : [ 0x00, ['long']],
            'y' : [ 0x04, ['long']],
            }],
            'tagHOOK' : [ None, {
            'head' : [ 0x0, ['_THRDESKHEAD']],
            'phkNext' : [ 0x14, ['pointer', ['tagHOOK']]],
            'iHook' : [ 0x18, ['long']],
            'offPfn' : [ 0x1c, ['unsigned long']],
            'flags': [ 0x20, ['Flags', {'bitmap': consts.HOOK_FLAGS}]],
            'ihmod' : [ 0x24, ['long']],
            'ptiHooked' : [ 0x28, ['pointer', ['tagTHREADINFO']]],
            'rpdesk' : [ 0x2c, ['pointer', ['tagDESKTOP']]],
            }],
            'tagDESKTOPINFO' : [ None, {
            'pvDesktopBase' : [ 0x0, ['pointer', ['void']]],
            'pvDesktopLimit' : [ 0x4, ['pointer', ['void']]],
            'spwnd' : [ 0x08, ['pointer', ['tagWND']]],
            'fsHooks' : [ 0x0c, ['unsigned long']],
            'aphkStart' : [ 0x10, ['array', 16, ['pointer', ['tagHOOK']]]],
            }],
            'tagSERVERINFO' : [ 0xffc, {
            'cHandleEntries' : [ 8, ['unsigned long']],
            'cbHandleTable' : [ 0x1bc, ['unsigned long']],
            }],
            'tagSHAREDINFO' : [ 0x11c, { # From Win7SP0x86
            'psi' : [ 0x0, ['pointer', ['tagSERVERINFO']]],
            'aheList' : [ 0x4, ['pointer', ['_HANDLEENTRY']]],
            'ulSharedDelta' : [ 0xC, ['unsigned long']],
            }],
            '_HANDLEENTRY' : [ 0xc, { # From Win7SP0x86
            'phead' : [ 0x0, ['pointer', ['_HEAD']]],
            'pOwner' : [ 0x4, ['pointer', ['void']]],
            'bType': [ 8, ['Enumeration', dict(target = 'unsigned char', choices = consts.HANDLE_TYPE_ENUM)]],
            'bFlags' : [ 0x9, ['unsigned char']],
            'wUniq' : [ 0xa, ['unsigned short']],
            }],
            '_HEAD' : [ 0x8, { # From Win7SP0x86
            'h' : [ 0x0, ['pointer', ['void']]],
            'cLockObj' : [ 0x4, ['unsigned long']],
            }],
            'tagPROCESSINFO' : [ None, {
            'Process' : [ 0x0, ['pointer', ['_EPROCESS']]],
            }],
            '_THRDESKHEAD' : [ 0x14, {
            'h' : [ 0x0, ['pointer', ['void']]],
            'cLockObj' : [ 0x4, ['unsigned long']],
            'pti' : [ 0x8, ['pointer', ['tagTHREADINFO']]],
            'rpdesk' : [ 0xc, ['pointer', ['tagDESKTOP']]],
            'pSelf' : [ 0x10, ['pointer', ['unsigned char']]],
            }],
            'tagCLS' : [ 0x5c, {
            'pclsNext' : [ 0x0, ['pointer', ['tagCLS']]],
            'atomClassName' : [ 0x4, ['unsigned short']],
            'atomNVClassName' : [ 0x6, ['unsigned short']],
            }],
            'tagRECT' : [ 0x10, {
            'left' : [ 0x0, ['long']],
            'top' : [ 0x4, ['long']],
            'right' : [ 0x8, ['long']],
            'bottom' : [ 0xc, ['long']],
            }],
            'tagWND' : [ 0xA4, {
            'head' : [ 0x0, ['_THRDESKHEAD']],
            'ExStyle' : [ 0x1c, ['unsigned long']],
            'style' : [ 0x20, ['unsigned long']],
            'hModule' : [ 0x24, ['pointer', ['void']]],
            'spwndNext' : [ 0x2c, ['pointer', ['tagWND']]],
            'spwndPrev' : [ 0x30, ['pointer', ['tagWND']]],
            'spwndParent' : [ 0x34, ['pointer', ['tagWND']]],
            'spwndChild' : [ 0x38, ['pointer', ['tagWND']]],
            'spwndOwner' : [ 0x3c, ['pointer', ['tagWND']]],
            'rcWindow' : [ 0x40, ['tagRECT']],
            'rcClient' : [ 0x50, ['tagRECT']],
            'lpfnWndProc' : [ 0x60, ['pointer', ['void']]],
            'pcls' : [ 0x64, ['pointer', ['tagCLS']]],
            'strName' : [ 0x80, ['_LARGE_UNICODE_STRING']],
            'cbwndExtra' : [ 0x8C, ['long']],
            'dwUserData' : [ 0x98, ['unsigned long']],
            }],
            '_LARGE_UNICODE_STRING' : [ 0xc, {
            'Length' : [ 0x0, ['unsigned long']],
            'MaximumLength' : [ 0x4, ['BitField', dict(start_bit = 0, end_bit = 31)]],
            'bAnsi' : [ 0x4, ['BitField', dict(start_bit = 31, end_bit = 32)]],
            'Buffer' : [ 0x8, ['pointer', ['unsigned short']]],
            }],
        })


class XP2003x64BaseVTypes(obj.ProfileModification):
    """Applies to Windows XP and 2003 x64"""

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x < 6}

    def modification(self, profile):

        profile.vtypes.update({
            'tagWINDOWSTATION' : [ 0x90, { # !poolfind Wind is 100h 
            'dwSessionId' : [ 0x0, ['unsigned long']],
            'rpwinstaNext' : [ 0x8, ['pointer64', ['tagWINDOWSTATION']]], # FreeWindowStation
            'rpdeskList' : [ 0x10, ['pointer64', ['tagDESKTOP']]],
            'dwWSF_Flags' : [ 0x20, ['unsigned long']], # FreeWindowStation
            'ptiDrawingClipboard' : [ 0x38, ['pointer64', ['tagTHREADINFO']]], # xxxDrawClipboard
            'spwndClipOpen' : [ 0x40, ['pointer64', ['tagWND']]],
            'spwndClipViewer' : [ 0x48, ['pointer64', ['tagWND']]],
            'spwndClipOwner' : [ 0x50, ['pointer64', ['tagWND']]],
            'pClipBase' : [ 0x58, ['pointer64', ['array', lambda x : x.cNumClipFormats, ['tagCLIP']]]], # InternalSetClipboardData
            'cNumClipFormats' : [ 0x60, ['unsigned int']], # InternalSetClipboardData
            'iClipSerialNumber' : [ 0x64, ['unsigned int']], # InternalSetClipboardData
            'iClipSequenceNumber' : [ 0x68, ['unsigned int']], # InternalSetClipboardData
            'pGlobalAtomTable' : [ 0x70, ['pointer64', ['void']]],
            }],

            # From Windows 7 
            'tagCLIP' : [ 0x18, {
            'fmt' : [ 0x0, ['Enumeration', dict(target = 'unsigned long', choices = consts.CLIPBOARD_FORMAT_ENUM)]],
            'hData' : [ 0x8, ['pointer64', ['void']]],
            'fGlobalHandle' : [ 0x10, ['long']],
            }],

            'tagDESKTOP' : [ 0xd0, { # !poolfind Desk is 140h
            'dwSessionId' : [ 0x0, ['unsigned long']],
            'pDeskInfo' : [ 0x8, ['pointer64', ['tagDESKTOPINFO']]], # xxxCreateDesktop
            'rpdeskNext' : [ 0x18, ['pointer64', ['tagDESKTOP']]], # ParseDesktop
            'rpwinstaParent' : [ 0x20, ['pointer64', ['tagWINDOWSTATION']]],
            'hsectionDesktop' : [ 0x70, ['pointer64', ['void']]], # MapDesktop
            'pheapDesktop' : [ 0x78, ['pointer64', ['tagWIN32HEAP']]], # DesktopAlloc
            'PtiList' : [ 0xa0, ['_LIST_ENTRY']], # zzzJournalAttach
            }],

            'tagTHREADINFO' : [ None, {
            'pEThread' : [ 0x00, ['pointer', ['_ETHREAD']]],
            'ppi' : [ 0x68, ['pointer64', ['tagPROCESSINFO']]], # xxxSetThreadDesktop
            #'pq' : [ 0x30, ['pointer', ['tagQ']]], 
            'pDeskInfo' : [ 0x90, ['pointer64', ['tagDESKTOPINFO']]], # xxxDesktopThread
            'PtiLink' : [ 0x160, ['_LIST_ENTRY']],
            'fsHooks' : [ 0x138, ['unsigned long']], # xxxSetThreadDesktop, CheckWHFBits
            'aphkStart' : [ 0x140, ['array', 16, ['pointer64', ['tagHOOK']]]],
            }],

            'tagDESKTOPINFO' : [ None, {
            'pvDesktopBase' : [ 0x0, ['pointer64', ['void']]],
            'pvDesktopLimit' : [ 0x8, ['pointer64', ['void']]],
            'spwnd' : [ 0x10, ['pointer64', ['tagWND']]],
            'fsHooks' : [ 0x18, ['unsigned long']], # CheckWHFBits
            'aphkStart' : [ 0x20, ['array', 16, ['pointer64', ['tagHOOK']]]],
            }],

            'tagWND' : [ None, {
            'head' : [ 0x0, ['_THRDESKHEAD']],
            'ExStyle' : [ 0x30, ['unsigned long']], # xxxCreateWindowEx
            'style' : [ 0x34, ['unsigned long']], # xxxCreateWindowEx
            'spwndNext' : [ 0x48, ['pointer64', ['tagWND']]],
            'spwndPrev' : [ 0x50, ['pointer64', ['tagWND']]],
            'spwndParent' : [ 0x58, ['pointer64', ['tagWND']]],
            'spwndChild' : [ 0x60, ['pointer64', ['tagWND']]],
            'spwndOwner' : [ 0x68, ['pointer64', ['tagWND']]],
            'rcWindow' : [ 0x70, ['tagRECT']],
            'rcClient' : [ 0x80, ['tagRECT']],
            'lpfnWndProc' : [ 0x90, ['pointer64', ['void']]],
            'pcls' : [ 0x98, ['pointer64', ['tagCLS']]], # HMChangeOwnerThread
            'strName' : [ 0xd0, ['_LARGE_UNICODE_STRING']],
            }],

            'tagRECT' : [ 0x10, {
            'left' : [ 0x0, ['long']],
            'top' : [ 0x4, ['long']],
            'right' : [ 0x8, ['long']],
            'bottom' : [ 0xc, ['long']],
            }],

            'tagCLS' : [ None, {
            'pclsNext' : [ 0x0, ['pointer64', ['tagCLS']]],
            'atomClassName' : [ 0x8, ['unsigned short']], # HMChangeOwnerThread
            'atomNVClassName' : [ 0xA, ['unsigned short']],
            }],

            # From Win7 x64
            '_LARGE_UNICODE_STRING' : [ 0x10, {
            'Length' : [ 0x0, ['unsigned long']],
            'MaximumLength' : [ 0x4, ['BitField', dict(start_bit = 0, end_bit = 31, native_type = 'unsigned long')]],
            'bAnsi' : [ 0x4, ['BitField', dict(start_bit = 31, end_bit = 32, native_type = 'unsigned long')]],
            'Buffer' : [ 0x8, ['pointer64', ['unsigned short']]],
            }],

            # From Win7 x64
            '_THRDESKHEAD' : [ 0x28, {
            'h' : [ 0x0, ['pointer64', ['void']]],
            'cLockObj' : [ 0x8, ['unsigned long']],
            'pti' : [ 0x10, ['pointer64', ['tagTHREADINFO']]],
            'rpdesk' : [ 0x18, ['pointer64', ['tagDESKTOP']]],
            'pSelf' : [ 0x20, ['pointer64', ['unsigned char']]],
            }],

            # From Win7 x64
            'tagSHAREDINFO' : [ None, {
            'psi' : [ 0x0, ['pointer64', ['tagSERVERINFO']]],
            'aheList' : [ 0x8, ['pointer64', ['_HANDLEENTRY']]],
            #'HeEntrySize' : [ 0x10, ['unsigned long']],
            #'pDispInfo' : [ 0x18, ['pointer64', ['tagDISPLAYINFO']]],
            'ulSharedDelta' : [ 0x18, ['unsigned long long']],
            #'awmControl' : [ 0x28, ['array', 31, ['_WNDMSG']]],
            #'DefWindowMsgs' : [ 0x218, ['_WNDMSG']],
            #'DefWindowSpecMsgs' : [ 0x228, ['_WNDMSG']],
            }],

            # From Win7 x64
            '_HANDLEENTRY' : [ 0x18, {
            'phead' : [ 0x0, ['pointer64', ['_HEAD']]],
            'pOwner' : [ 0x8, ['pointer64', ['void']]],
            'bType': [ 0x10, ['Enumeration', dict(target = 'unsigned char', choices = consts.HANDLE_TYPE_ENUM)]],
            'bFlags' : [ 0x11, ['unsigned char']],
            'wUniq' : [ 0x12, ['unsigned short']],
            }],

            # From Win7 x64
            '_HEAD' : [ 0x10, {
            'h' : [ 0x0, ['pointer64', ['void']]],
            'cLockObj' : [ 0x8, ['unsigned long']],
            }],

            'tagSERVERINFO' : [ None, {
            'cHandleEntries' : [ 8, ['unsigned long']],
            'cbHandleTable' : [ 0x330, ['unsigned long']], # HMInitHandleTable
            }],

            'tagPROCESSINFO' : [ None, {
            'Process' : [ 0x0, ['pointer', ['_EPROCESS']]],
            }],

            # From Win7 x64
            'tagHOOK' : [ 0x60, {
            'head' : [ 0x0, ['_THRDESKHEAD']],
            'phkNext' : [ 0x28, ['pointer64', ['tagHOOK']]],
            'iHook' : [ 0x30, ['long']],
            'offPfn' : [ 0x38, ['unsigned long long']],
            'flags': [ 0x40, ['Flags', {'bitmap': consts.HOOK_FLAGS}]],
            'ihmod' : [ 0x44, ['long']],
            'ptiHooked' : [ 0x48, ['pointer64', ['tagTHREADINFO']]],
            'rpdesk' : [ 0x50, ['pointer64', ['tagDESKTOP']]],
            'nTimeout' : [ 0x58, ['BitField', dict(start_bit = 0, end_bit = 7, native_type = 'unsigned long')]],
            'fLastHookHung' : [ 0x58, ['BitField', dict(start_bit = 7, end_bit = 8, native_type = 'long')]],
            }],
        })

