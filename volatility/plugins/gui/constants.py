# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
# Copyright (C) 2009 Brendan Dolan-Gavitt 
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

import copy

# Windows assigns several atom IDs by default, but doesn't include
# them in the local or global atom tables. Thus when we perform a 
# lookup, we don't want to exclude these default atoms, so we create 
# a fake atom structure and assign the values as needed. The search 
# algorithm will then check the default atoms before moving onto the 
# atoms found in local/global tables. 
class FakeAtom(object):
    def __init__(self, name):
        self.Name = name

DEFAULT_ATOMS = {
  0x8000: FakeAtom("PopupMenu (Default)"),
  0x8001: FakeAtom("Desktop (Default)"),
  0x8002: FakeAtom("Dialog (Default)"),
  0x8003: FakeAtom("WinSwitch (Default)"),
  0x8004: FakeAtom("IconTitle (Default)"),
  0x8006: FakeAtom("ToolTip (Default)"),
}

WINDOW_STYLES = dict(
  WS_OVERLAPPED = 0x00000000L,
  WS_POPUP = 0x80000000L,
  WS_CHILD = 0x40000000L,
  WS_MINIMIZE = 0x20000000L,
  WS_VISIBLE = 0x10000000L,
  WS_DISABLED = 0x08000000L,
  WS_CLIPSIBLINGS = 0x04000000L,
  WS_CLIPCHILDREN = 0x02000000L,
  WS_MAXIMIZE = 0x01000000L,
  WS_CAPTION = 0x00C00000L,
  WS_BORDER = 0x00800000L,
  WS_DLGFRAME = 0x00400000L,
  WS_VSCROLL = 0x00200000L,
  WS_HSCROLL = 0x00100000L,
  WS_SYSMENU = 0x00080000L,
  WS_THICKFRAME = 0x00040000L,
  WS_GROUP = 0x00020000L,
  WS_TABSTOP = 0x00010000L,
  WS_MINIMIZEBOX = 0x00020000L,
  WS_MAXIMIZEBOX = 0x00010000L,
)

WINDOW_STYLES_EX = dict(
  WS_EX_DLGMODALFRAME = 0x00000001L,
  WS_EX_NOPARENTNOTIFY = 0x00000004L,
  WS_EX_TOPMOST = 0x00000008L,
  WS_EX_ACCEPTFILES = 0x00000010L,
  WS_EX_TRANSPARENT = 0x00000020L,
  WS_EX_MDICHILD = 0x00000040L,
  WS_EX_TOOLWINDOW = 0x00000080L,
  WS_EX_WINDOWEDGE = 0x00000100L,
  WS_EX_CLIENTEDGE = 0x00000200L,
  WS_EX_CONTEXTHELP = 0x00000400L,
  WS_EX_RIGHT = 0x00001000L,
  WS_EX_LEFT = 0x00000000L,
  WS_EX_RTLREADING = 0x00002000L,
  WS_EX_LTRREADING = 0x00000000L,
  WS_EX_LEFTSCROLLBAR = 0x00004000L,
  WS_EX_RIGHTSCROLLBAR = 0x00000000L,
  WS_EX_CONTROLPARENT = 0x00010000L,
  WS_EX_STATICEDGE = 0x00020000L,
  WS_EX_APPWINDOW = 0x00040000L,
)

# These are message types in the order that they appear in the aphkStart array.
MESSAGE_TYPES = [
    ('WH_MSGFILTER', -1),
    ('WH_JOURNALRECORD', 0),
    ('WH_JOURNALPLAYBACK', 1),
    ('WH_KEYBOARD', 2),
    ('WH_GETMESSAGE', 3),
    ('WH_CALLWNDPROC', 4),
    ('WH_CBT', 5),
    ('WH_SYSMSGFILTER', 6),
    ('WH_MOUSE', 7),
    ('WH_HARDWARE', 8),
    ('WH_DEBUG', 9),
    ('WH_SHELL', 10),
    ('WH_FOREGROUNDIDLE', 11),
    ('WH_CALLWNDPROCRET', 12),
    ('WH_KEYBOARD_LL', 13),
    ('WH_MOUSE_LL', 14),
    ]

# See http://forum.sysinternals.com/enumerate-windows-hooks_topic23877_post124845.html
HOOK_FLAGS = dict(
    HF_GLOBAL = 0, #0x0001, # Global hooks (for all threads on desktop)
    HF_ANSI = 1, #0x0002, # Uses Ansi strings instead of Unicode 
    HF_HUNG = 3, #0x0008, # The hook procedure is hung
    HF_HOOKFAULTED = 4, #0x0010, # The hook procedure caused some fault 
    HF_WX86KNOWNDLL = 6, #0x0040, # Hook Module is x86 machine type
    HF_DESTROYED = 7, #0x0080, # The object is destroyed (set by FreeHook)
    HF_INCHECKWHF = 8, #0x0100, # The fsHooks is currently being updated
    HF_FREED = 9, #0x0200, # The object is freed
    )

# dwflags parameter to SetWinEventHook
EVENT_FLAGS = {
    #0x0000 : 'WINEVENT_OUTOFCONTEXT',
    0x0001 : 'WINEVENT_SKIPOWNTHREAD',
    0x0002 : 'WINEVENT_SKIPOWNPROCESS',
    0x0004 : 'WINEVENT_INCONTEXT',
}

# The eventMin and eventMax parameters to SetWinEventHook. 
EVENT_ID_ENUM = {
    0x00000001: 'EVENT_MIN',
    0x7FFFFFFF: 'EVENT_MAX',
    #0x0001: 'EVENT_SYSTEM_SOUND',
    0x0002: 'EVENT_SYSTEM_ALERT',
    0x0003: 'EVENT_SYSTEM_FOREGROUND',
    0x0004: 'EVENT_SYSTEM_MENUSTART',
    0x0005: 'EVENT_SYSTEM_MENUEND',
    0x0006: 'EVENT_SYSTEM_MENUPOPUPSTART',
    0x0007: 'EVENT_SYSTEM_MENUPOPUPEND',
    0x0008: 'EVENT_SYSTEM_CAPTURESTART',
    0x0009: 'EVENT_SYSTEM_CAPTUREEND',
    0x000A: 'EVENT_SYSTEM_MOVESIZESTART',
    0x000B: 'EVENT_SYSTEM_MOVESIZEEND',
    0x000C: 'EVENT_SYSTEM_CONTEXTHELPSTART',
    0x000D: 'EVENT_SYSTEM_CONTEXTHELPEND',
    0x000E: 'EVENT_SYSTEM_DRAGDROPSTART',
    0x000F: 'EVENT_SYSTEM_DRAGDROPEND',
    0x0010: 'EVENT_SYSTEM_DIALOGSTART',
    0x0011: 'EVENT_SYSTEM_DIALOGEND',
    0x0012: 'EVENT_SYSTEM_SCROLLINGSTART',
    0x0013: 'EVENT_SYSTEM_SCROLLINGEND',
    0x0014: 'EVENT_SYSTEM_SWITCHSTART',
    0x0015: 'EVENT_SYSTEM_SWITCHEND',
    0x0016: 'EVENT_SYSTEM_MINIMIZESTART',
    0x0017: 'EVENT_SYSTEM_MINIMIZEEND',
    0x0020: 'EVENT_SYSTEM_DESKTOPSWITCH',
    0x00FF: 'EVENT_SYSTEM_END',
    0x0101: 'EVENT_OEM_DEFINED_START',
    0x01FF: 'EVENT_OEM_DEFINED_END',
    0x4E00: 'EVENT_UIA_EVENTID_START',
    0x4EFF: 'EVENT_UIA_EVENTID_END',
    0x7500: 'EVENT_UIA_PROPID_START',
    0x75FF: 'EVENT_UIA_PROPID_END',
    0x4001: 'EVENT_CONSOLE_CARET',
    0x4002: 'EVENT_CONSOLE_UPDATE_REGION',
    0x4003: 'EVENT_CONSOLE_UPDATE_SIMPLE',
    0x4004: 'EVENT_CONSOLE_UPDATE_SCROLL',
    0x4005: 'EVENT_CONSOLE_LAYOUT',
    0x4006: 'EVENT_CONSOLE_START_APPLICATION',
    0x4007: 'EVENT_CONSOLE_END_APPLICATION',
    0x40FF: 'EVENT_CONSOLE_END',
    0x8000: 'EVENT_OBJECT_CREATE',
    0x8001: 'EVENT_OBJECT_DESTROY',
    0x8002: 'EVENT_OBJECT_SHOW',
    0x8003: 'EVENT_OBJECT_HIDE',
    0x8004: 'EVENT_OBJECT_REORDER',
    0x8005: 'EVENT_OBJECT_FOCUS',
    0x8006: 'EVENT_OBJECT_SELECTION',
    0x8007: 'EVENT_OBJECT_SELECTIONADD',
    0x8008: 'EVENT_OBJECT_SELECTIONREMOVE',
    0x8009: 'EVENT_OBJECT_SELECTIONWITHIN',
    0x800A: 'EVENT_OBJECT_STATECHANGE',
    0x800B: 'EVENT_OBJECT_LOCATIONCHANGE',
    0x800C: 'EVENT_OBJECT_NAMECHANGE',
    0x800D: 'EVENT_OBJECT_DESCRIPTIONCHANGE',
    0x800E: 'EVENT_OBJECT_VALUECHANGE',
    0x800F: 'EVENT_OBJECT_PARENTCHANGE',
    0x8010: 'EVENT_OBJECT_HELPCHANGE',
    0x8011: 'EVENT_OBJECT_DEFACTIONCHANGE',
    0x8012: 'EVENT_OBJECT_ACCELERATORCHANGE',
    0x8013: 'EVENT_OBJECT_INVOKED',
    0x8014: 'EVENT_OBJECT_TEXTSELECTIONCHANGED',
}

# USER objects on XP/2003/Vista/2008
HANDLE_TYPE_ENUM = {
    0: 'TYPE_FREE',
    1: 'TYPE_WINDOW',
    2: 'TYPE_MENU',
    3: 'TYPE_CURSOR',
    4: 'TYPE_SETWINDOWPOS',
    5: 'TYPE_HOOK',
    6: 'TYPE_CLIPDATA',
    7: 'TYPE_CALLPROC',
    8: 'TYPE_ACCELTABLE',
    9: 'TYPE_DDEACCESS',
   10: 'TYPE_DDECONV',
   11: 'TYPE_DDEXACT',
   12: 'TYPE_MONITOR',
   13: 'TYPE_KBDLAYOUT',
   14: 'TYPE_KBDFILE',
   15: 'TYPE_WINEVENTHOOK',
   16: 'TYPE_TIMER',
   17: 'TYPE_INPUTCONTEXT',
   18: 'TYPE_HIDDATA',
   19: 'TYPE_DEVICEINFO',
}

# USER objects for Windows 7 
HANDLE_TYPE_ENUM_SEVEN = copy.copy(HANDLE_TYPE_ENUM)
HANDLE_TYPE_ENUM_SEVEN[20] = 'TYPE_TOUCH'
HANDLE_TYPE_ENUM_SEVEN[21] = 'TYPE_GESTURE'

# Clipboard format types
CLIPBOARD_FORMAT_ENUM = {
    1: 'CF_TEXT',
    2: 'CF_BITMAP',
    3: 'CF_METAFILEPICT',
    4: 'CF_SYLK',
    5: 'CF_DIF',
    6: 'CF_TIFF',
    7: 'CF_OEMTEXT',
    8: 'CF_DIB',
    9: 'CF_PALETTE',
    10: 'CF_PENDATA',
    11: 'CF_RIFF',
    12: 'CF_WAVE',
    13: 'CF_UNICODETEXT',
    14: 'CF_ENHMETAFILE',
    15: 'CF_HDROP',
    16: 'CF_LOCALE',
    17: 'CF_DIBV5',
    0x80: 'CF_OWNERDISPLAY',
    0x81: 'CF_DSPTEXT',
    0x82: 'CF_DSPBITMAP',
    0x83: 'CF_DSPMETAFILEPICT',
    0x8E: 'CF_DSPENHMETAFILE',
    ## The following are ranges, not actual formats 
    #0x200: 'CF_PRIVATEFIRST', 
    #0x2FF: 'CF_PRIVATELAST', 
    #0x300: 'CF_GDIOBJFIRST', 
    #0x3FF: 'CF_GDIOBJLAST', 
}

# Flags for timer objects 
TIMER_FLAGS = dict(
    TMRF_READY = 0, # 0x0001
    TMRF_SYSTEM = 1, # 0x0002
    TMRF_RIT = 2, # 0x0004
    TMRF_INIT = 3, # 0x0008
    TMRF_ONESHOT = 4, # 0x0010
    TMRF_WAITING = 5, # 0x0020
    TMRF_TIFROMWND = 6, # 0x0040
)
