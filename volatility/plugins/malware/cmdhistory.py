# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# Authors:
# Michael Hale Ligh <michael.ligh@mnin.org>
#
# Contributors/References:
#   Richard Stevens and Eoghan Casey
#   Extracting Windows Cmd Line Details from Physical Memory.
#   http://ww.dfrws.org/2010/proceedings/stevens.pdf
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
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.debug as debug
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex

MAX_HISTORY_DEFAULT = 50

#--------------------------------------------------------------------------------
# VTypes
#--------------------------------------------------------------------------------

# Windows 7 Types from conhost.exe
conhost_types_x86 = {
    '_COMMAND': [ None, {
    'CmdLength': [ 0x00, ['unsigned short']],
    'Cmd' : [ 0x02, ['String', dict(encoding = 'utf16', length = lambda x : x.CmdLength)]],
    }],
    '_COMMAND_HISTORY': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'Flags' : [ 0x08, ['Flags', {'bitmap': {'Allocated': 0, 'Reset': 1}}]],
    'Application': [ 0x0C, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'CommandCount': [ 0x10, ['short']],
    'LastAdded': [ 0x12, ['short']],
    'LastDisplayed': [ 0x14, ['short']],
    'FirstCommand': [ 0x16, ['short']],
    'CommandCountMax': [ 0x18, ['short']],
    'ProcessHandle': [ 0x1C, ['unsigned int']],
    'PopupList': [ 0x20, ['_LIST_ENTRY']],
    'CommandBucket': [ 0x28, ['array', lambda x : x.CommandCount, ['pointer', ['_COMMAND']]]],
    }],
    '_ALIAS': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'SourceLength': [ 0x08, ['unsigned short']],
    'TargetLength': [ 0x0A, ['unsigned short']],
    'Source': [ 0x0C, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.SourceLength)]]],
    'Target': [ 0x10, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.TargetLength)]]],
    }],
    '_EXE_ALIAS_LIST' : [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'ExeLength': [ 0x08, ['unsigned short']],
    'ExeName': [ 0x0C, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.ExeLength * 2)]]],
    'AliasList': [ 0x10, ['_LIST_ENTRY']],
    }],
    '_POPUP_LIST' : [ None, {
    'ListEntry' : [ 0x00, ['_LIST_ENTRY']],
    }],
    '_CONSOLE_INFORMATION': [ None, {
    'CurrentScreenBuffer': [ 0x98, ['pointer', ['_SCREEN_INFORMATION']]],
    'ScreenBuffer': [ 0x9C, ['pointer', ['_SCREEN_INFORMATION']]],
    'HistoryList': [ 0xD4, ['_LIST_ENTRY']],
    'ProcessList': [ 0x18, ['_LIST_ENTRY']], # GetConsoleProcessList()
    'ExeAliasList': [ 0xDC, ['_LIST_ENTRY']], # GetConsoleAliasExes() 
    'HistoryBufferCount': [ 0xE4, ['unsigned short']], # GetConsoleHistoryInfo()
    'HistoryBufferMax': [ 0xE6, ['unsigned short']], # GetConsoleHistoryInfo()
    'CommandHistorySize': [ 0xE8, ['unsigned short']],
    'OriginalTitle': [ 0xEC, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]], # GetConsoleOriginalTitle()
    'Title': [ 0xF0, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]], # GetConsoleTitle()
    }],
    '_CONSOLE_PROCESS': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'ProcessHandle': [ 0x8, ['unsigned int']],
    }],
    '_SCREEN_INFORMATION': [ None, {
    'ScreenX': [ 0x08, ['short']],
    'ScreenY': [ 0x0A, ['short']],
    'Rows': [ 0x3C, ['pointer', ['array', lambda x : x.ScreenY, ['_ROW']]]],
    'Next': [ 0xDC, ['pointer', ['_SCREEN_INFORMATION']]],
    }],
    '_ROW': [ 0x1C, {
    'Chars': [ 0x08, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    }],
}

# Windows 7 Types from conhost.exe
conhost_types_x64 = {
    '_COMMAND': [ None, {
    'CmdLength': [ 0x00, ['unsigned short']],
    'Cmd' : [ 0x02, ['String', dict(encoding = 'utf16', length = lambda x : x.CmdLength)]],
    }],
    '_COMMAND_HISTORY': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']], 
    'Flags' : [ 0x10, ['Flags', {'bitmap': {'Allocated': 0, 'Reset': 1}}]], # AllocateCommandHistory()
    'Application': [ 0x18, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]], # AllocateCommandHistory()
    'CommandCount': [ 0x20, ['short']], 
    'LastAdded': [ 0x22, ['short']], 
    'LastDisplayed': [ 0x24, ['short']],
    'FirstCommand': [ 0x26, ['short']], 
    'CommandCountMax': [ 0x28, ['short']], # AllocateCommandHistory()
    'ProcessHandle': [ 0x30, ['address']], # AllocateCommandHistory()
    'PopupList': [ 0x38, ['_LIST_ENTRY']], # AllocateCommandHistory()
    'CommandBucket': [ 0x48, ['array', lambda x : x.CommandCount, ['pointer', ['_COMMAND']]]], 
    }],
    '_ALIAS': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']], 
    'SourceLength': [ 0x10, ['unsigned short']], # AddAlias()
    'TargetLength': [ 0x12, ['unsigned short']], # AddAlias()
    'Source': [ 0x18, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.SourceLength)]]], # AddAlias()
    'Target': [ 0x20, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.TargetLength)]]], # AddAlias()
    }],
    '_EXE_ALIAS_LIST' : [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']], 
    'ExeLength': [ 0x10, ['unsigned short']], # AddExeAliasList()
    'ExeName': [ 0x18, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.ExeLength * 2)]]], # AddExeAliasList()
    'AliasList': [ 0x20, ['_LIST_ENTRY']], # AddExeAliasList()
    }],
    '_POPUP_LIST' : [ None, {
    'ListEntry' : [ 0x00, ['_LIST_ENTRY']],
    }],
    '_CONSOLE_INFORMATION': [ None, {
    'ProcessList': [ 0x28, ['_LIST_ENTRY']], # SrvGetConsoleProcessList()
    'CurrentScreenBuffer': [ 0xE0, ['pointer', ['_SCREEN_INFORMATION']]], # AllocateConsole()
    'ScreenBuffer': [ 0xE8, ['pointer', ['_SCREEN_INFORMATION']]], # AllocateConsole()
    'HistoryList': [ 0x148, ['_LIST_ENTRY']], # AllocateCommandHistory()
    'ExeAliasList': [ 0x158, ['_LIST_ENTRY']], # SrvGetConsoleAliasExes()
    'HistoryBufferCount': [ 0x168, ['unsigned short']], # AllocateConsole()
    'HistoryBufferMax': [ 0x16A, ['unsigned short']], # AllocateConsole()
    'CommandHistorySize': [ 0x16C, ['unsigned short']], # AllocateConsole()
    'OriginalTitle': [ 0x170, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]], # SrvGetConsoleTitle()
    'Title': [ 0x178, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]], # SrvGetConsoleTitle()
    }],
    '_CONSOLE_PROCESS': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'ProcessHandle': [ 0x10, ['unsigned int']], # FindProcessInList()
    }],
    '_SCREEN_INFORMATION': [ None, {
    'ScreenX': [ 8, ['short']], 
    'ScreenY': [ 10, ['short']], 
    'Rows': [ 0x48, ['pointer', ['array', lambda x : x.ScreenY, ['_ROW']]]], 
    'Next': [ 0x128, ['pointer', ['_SCREEN_INFORMATION']]],
    }],
    '_ROW': [ 0x28, { 
    'Chars': [ 0x08, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]], 
    }],
}

# Windows XP, 2003, 2008, Vista from winsrv.dll
winsrv_types_x86 = {
    '_COMMAND': [ None, {
    'CmdLength': [ 0x00, ['unsigned short']],
    'Cmd' : [ 0x02, ['String', dict(encoding = 'utf16', length = lambda x : x.CmdLength)]],
    }],
    '_COMMAND_HISTORY': [ None, {
    'Flags' : [ 0x00, ['Flags', {'bitmap': {'Allocated': 0, 'Reset': 1}}]],
    'ListEntry': [ 0x04, ['_LIST_ENTRY']],
    'Application': [ 0x0C, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'CommandCount': [ 0x10, ['short']],
    'LastAdded': [ 0x12, ['short']],
    'LastDisplayed': [ 0x14, ['short']],
    'FirstCommand': [ 0x16, ['short']],
    'CommandCountMax': [ 0x18, ['short']],
    'ProcessHandle': [ 0x1C, ['unsigned int']],
    'PopupList': [ 0x20, ['_LIST_ENTRY']],
    'CommandBucket': [ 0x28, ['array', lambda x : x.CommandCount, ['pointer', ['_COMMAND']]]],
    }],
    '_ALIAS': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'SourceLength': [ 0x08, ['unsigned short']],
    'TargetLength': [ 0x0A, ['unsigned short']],
    'Source': [ 0x0C, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.SourceLength)]]],
    'Target': [ 0x10, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.TargetLength)]]],
    }],
    '_EXE_ALIAS_LIST' : [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'ExeLength': [ 0x08, ['unsigned short']],
    'ExeName': [ 0x0C, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.ExeLength * 2)]]],
    'AliasList': [ 0x10, ['_LIST_ENTRY']],
    }],
    '_POPUP_LIST' : [ None, {
    'ListEntry' : [ 0x00, ['_LIST_ENTRY']],
    }],
    '_CONSOLE_INFORMATION': [ None, {
    'CurrentScreenBuffer': [ 0xB0, ['pointer', ['_SCREEN_INFORMATION']]],
    'ScreenBuffer': [ 0xB4, ['pointer', ['_SCREEN_INFORMATION']]],
    'HistoryList': [ 0x108, ['_LIST_ENTRY']],
    'ProcessList': [ 0x100, ['_LIST_ENTRY']],
    'ExeAliasList': [ 0x110, ['_LIST_ENTRY']],
    'HistoryBufferCount': [ 0x118, ['unsigned short']],
    'HistoryBufferMax': [ 0x11A, ['unsigned short']],
    'CommandHistorySize': [ 0x11C, ['unsigned short']],
    'OriginalTitle': [ 0x124, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'Title': [ 0x128, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    }],
    '_CONSOLE_PROCESS': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'ProcessHandle': [ 0x08, ['unsigned int']],
    'Process': [ 0x0C, ['pointer', ['_CSR_PROCESS']]],
    }],
    '_SCREEN_INFORMATION': [ None, {
    'Console': [ 0x00, ['pointer', ['_CONSOLE_INFORMATION']]],
    'ScreenX': [ 0x24, ['short']],
    'ScreenY': [ 0x26, ['short']],
    'Rows': [ 0x58, ['pointer', ['array', lambda x : x.ScreenY, ['_ROW']]]],
    'Next': [ 0xF8, ['pointer', ['_SCREEN_INFORMATION']]],
    }],
    '_ROW': [ 0x1C, {
    'Chars': [ 0x08, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    }],
    '_CSR_PROCESS' : [ 0x60, { # this is a public PDB  
    'ClientId' : [ 0x0, ['_CLIENT_ID']],
    'ListLink' : [ 0x8, ['_LIST_ENTRY']],
    'ThreadList' : [ 0x10, ['_LIST_ENTRY']],
    'NtSession' : [ 0x18, ['pointer', ['_CSR_NT_SESSION']]],
    'ClientPort' : [ 0x1c, ['pointer', ['void']]],
    'ClientViewBase' : [ 0x20, ['pointer', ['unsigned char']]],
    'ClientViewBounds' : [ 0x24, ['pointer', ['unsigned char']]],
    'ProcessHandle' : [ 0x28, ['pointer', ['void']]],
    'SequenceNumber' : [ 0x2c, ['unsigned long']],
    'Flags' : [ 0x30, ['unsigned long']],
    'DebugFlags' : [ 0x34, ['unsigned long']],
    'ReferenceCount' : [ 0x38, ['unsigned long']],
    'ProcessGroupId' : [ 0x3c, ['unsigned long']],
    'ProcessGroupSequence' : [ 0x40, ['unsigned long']],
    'LastMessageSequence' : [ 0x44, ['unsigned long']],
    'NumOutstandingMessages' : [ 0x48, ['unsigned long']],
    'ShutdownLevel' : [ 0x4c, ['unsigned long']],
    'ShutdownFlags' : [ 0x50, ['unsigned long']],
    'Luid' : [ 0x54, ['_LUID']],
    'ServerDllPerProcessData' : [ 0x5c, ['array', 1, ['pointer', ['void']]]],
    }],
}

winsrv_types_x64 = {
    '_COMMAND': [ None, {
    'CmdLength': [ 0x00, ['unsigned short']],
    'Cmd' : [ 0x02, ['String', dict(encoding = 'utf16', length = lambda x : x.CmdLength)]],
    }],
    '_COMMAND_HISTORY': [ None, {
    'Flags' : [ 0x00, ['Flags', {'bitmap': {'Allocated': 0, 'Reset': 1}}]],
    'ListEntry': [ 0x08, ['_LIST_ENTRY']],
    'Application': [ 0x18, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'CommandCount': [ 0x20, ['short']],
    'LastAdded': [ 0x22, ['short']],
    'LastDisplayed': [ 0x24, ['short']],
    'FirstCommand': [ 0x26, ['short']],
    'CommandCountMax': [ 0x28, ['short']],
    'ProcessHandle': [ 0x30, ['unsigned int']],
    'PopupList': [ 0x38, ['_LIST_ENTRY']],
    'CommandBucket': [ 0x48, ['array', lambda x : x.CommandCount, ['pointer', ['_COMMAND']]]],
    }],
    '_ALIAS': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'SourceLength': [ 0x10, ['unsigned short']],
    'TargetLength': [ 0x12, ['unsigned short']],
    'Source': [ 0x14, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.SourceLength)]]],
    'Target': [ 0x1C, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.TargetLength)]]],
    }],
    '_EXE_ALIAS_LIST' : [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'ExeLength': [ 0x10, ['unsigned short']],
    'ExeName': [ 0x12, ['pointer', ['String', dict(encoding = 'utf16', length = lambda x : x.ExeLength * 2)]]],
    'AliasList': [ 0x1A, ['_LIST_ENTRY']],
    }],
    '_POPUP_LIST' : [ None, {
    'ListEntry' : [ 0x00, ['_LIST_ENTRY']],
    }],
    '_CONSOLE_INFORMATION': [ None, {
    'CurrentScreenBuffer': [ 0xE8, ['pointer', ['_SCREEN_INFORMATION']]],
    'ScreenBuffer': [ 0xF0, ['pointer', ['_SCREEN_INFORMATION']]],
    'HistoryList': [ 0x188, ['_LIST_ENTRY']],
    'ProcessList': [ 0x178, ['_LIST_ENTRY']],
    'ExeAliasList': [ 0x198, ['_LIST_ENTRY']],
    'HistoryBufferCount': [ 0x1A8, ['unsigned short']],
    'HistoryBufferMax': [ 0x1AA, ['unsigned short']],
    'CommandHistorySize': [ 0x1AC, ['unsigned short']],
    'OriginalTitle': [ 0x1B0, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'Title': [ 0x1B8, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    }],
    '_CONSOLE_PROCESS': [ None, {
    'ListEntry': [ 0x00, ['_LIST_ENTRY']],
    'ProcessHandle': [ 0x10, ['unsigned int']],
    'Process': [ 0x18, ['pointer', ['_CSR_PROCESS']]],
    }],
    '_SCREEN_INFORMATION': [ None, {
    'Console': [ 0x00, ['pointer', ['_CONSOLE_INFORMATION']]],
    'ScreenX': [ 0x28, ['short']],
    'ScreenY': [ 0x2A, ['short']],
    'Rows': [ 0x68, ['pointer', ['array', lambda x : x.ScreenY, ['_ROW']]]],
    'Next': [ 0x128, ['pointer', ['_SCREEN_INFORMATION']]],
    }],
    '_ROW': [ 0x28, {
    'Chars': [ 0x08, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    }],
    '_CSR_PROCESS' : [ 0x60, { # this is a public PDB  
    'ClientId' : [ 0x0, ['_CLIENT_ID']],
    'ListLink' : [ 0x8, ['_LIST_ENTRY']],
    'ThreadList' : [ 0x10, ['_LIST_ENTRY']],
    'NtSession' : [ 0x18, ['pointer', ['_CSR_NT_SESSION']]],
    'ClientPort' : [ 0x1c, ['pointer', ['void']]],
    'ClientViewBase' : [ 0x20, ['pointer', ['unsigned char']]],
    'ClientViewBounds' : [ 0x24, ['pointer', ['unsigned char']]],
    'ProcessHandle' : [ 0x28, ['pointer', ['void']]],
    'SequenceNumber' : [ 0x2c, ['unsigned long']],
    'Flags' : [ 0x30, ['unsigned long']],
    'DebugFlags' : [ 0x34, ['unsigned long']],
    'ReferenceCount' : [ 0x38, ['unsigned long']],
    'ProcessGroupId' : [ 0x3c, ['unsigned long']],
    'ProcessGroupSequence' : [ 0x40, ['unsigned long']],
    'LastMessageSequence' : [ 0x44, ['unsigned long']],
    'NumOutstandingMessages' : [ 0x48, ['unsigned long']],
    'ShutdownLevel' : [ 0x4c, ['unsigned long']],
    'ShutdownFlags' : [ 0x50, ['unsigned long']],
    'Luid' : [ 0x54, ['_LUID']],
    'ServerDllPerProcessData' : [ 0x5c, ['array', 1, ['pointer', ['void']]]],
    }],
}

#--------------------------------------------------------------------------------
# Object Classes 
#--------------------------------------------------------------------------------

class _CONSOLE_INFORMATION(obj.CType):
    """ object class for console information structs """

    def get_histories(self):
        for hist in self.HistoryList.list_of_type("_COMMAND_HISTORY", "ListEntry"):
            yield hist

    def get_exe_aliases(self):
        """Generator for exe aliases.

        There is one _EXE_ALIAS_LIST for each executable 
        (i.e. C:\windows\system32\cmd.exe) with registered
        aliases. The _EXE_ALIAS_LIST.AliasList contains 
        one _ALIAS structure for each specific mapping.

        See GetConsoleAliasExes, GetConsoleAliases, and  
        AddConsoleAlias. 
        """
        for exe_alias in self.ExeAliasList.list_of_type("_EXE_ALIAS_LIST", "ListEntry"):
            yield exe_alias

    def get_processes(self):
        """Generator for processes attached to the console. 

        Multiple processes can be attached to the same
        console (usually as a result of inheritance from a 
        parent process or by duplicating another process's 
        console handle). Internally, they are tracked as 
        _CONSOLE_PROCESS structures in this linked list. 

        See GetConsoleProcessList and AttachConsole. 
        """
        for h in self.ProcessList.list_of_type("_CONSOLE_PROCESS", "ListEntry"):
            yield h

    def get_screens(self):
        """Generator for screens in the console. 

        A console can have multiple screen buffers at a time, 
        but only the current/active one is displayed. 

        Multiple screens are tracked using the singly-linked
        list _SCREEN_INFORMATION.Next. 
    
        See CreateConsoleScreenBuffer 
        """
        screens = [self.CurrentScreenBuffer]

        if self.ScreenBuffer not in screens:
            screens.append(self.ScreenBuffer)

        for screen in screens:
            cur = screen
            while cur and cur.v() != 0:
                yield cur
                cur = cur.Next.dereference()

class _CONSOLE_PROCESS(obj.CType):
    """ object class for console process """

    def reference_object_by_handle(self):
        """ Given a process handle, return a reference to 
        the _EPROCESS object. This function is similar to 
        the kernel API ObReferenceObjectByHandle. """

        console_information = self.obj_parent
        parent_process = console_information.obj_parent

        for h in parent_process.ObjectTable.handles():
            if h.HandleValue == self.ProcessHandle:
                return h.dereference_as("_EPROCESS")

        return obj.NoneObject("Could not find process in handle table")

class _SCREEN_INFORMATION(obj.CType):
    """ object class for screen information """

    def get_buffer(self, truncate = True):
        """Get the screen buffer. 

        The screen buffer is comprised of the screen's Y 
        coordinate which tells us the number of rows and 
        the X coordinate which tells us the width of each
        row in characters. These together provide all of 
        the input and output that users see when the 
        console is displayed. 

        @param truncate: True if the empty rows at the 
        end (i.e. bottom) of the screen buffer should be 
        supressed.
        """
        rows = []

        for _, row in enumerate(self.Rows.dereference()):
            if row.Chars.is_valid():
                rows.append(str(row.Chars.dereference())[0:self.ScreenX])

        # To truncate empty rows at the end, walk the list
        # backwards and get the last non-empty row. Use that
        # row index to splice. An "empty" row isn't just "" 
        # as one might assume. It is actually ScreenX number 
        # of space characters

        if truncate:
            non_empty_index = 0
            for index, row in enumerate(reversed(rows)):
                ## It seems that when the buffer width is greater than 128 
                ## characters, its truncated to 128 in memory. 
                if row.count(" ") != min(self.ScreenX, 128):
                    non_empty_index = index
                    break
            if non_empty_index == 0:
                rows = []
            else:
                rows = rows[0:len(rows) - non_empty_index]

        return rows

class _EXE_ALIAS_LIST(obj.CType):
    """ object class for alias lists """

    def get_aliases(self):
        """Generator for the individual aliases for a
        particular executable."""
        for alias in self.AliasList.list_of_type("_ALIAS", "ListEntry"):
            yield alias

class _COMMAND_HISTORY(obj.CType):
    """ object class for command histories """

    def is_valid(self, max_history = MAX_HISTORY_DEFAULT): #pylint: disable-msg=W0221
        """Override BaseObject.is_valid with some additional
        checks specific to _COMMAND_HISTORY objects."""

        if not obj.CType.is_valid(self):
            return False

        # The count must be between zero and max 
        if self.CommandCount < 0 or self.CommandCount > max_history:
            return False

        # Last added must be between -1 and max 
        if self.LastAdded < -1 or self.LastAdded > max_history:
            return False

        # Last displayed must be between -1 and max
        if self.LastDisplayed < -1 or self.LastDisplayed > max_history:
            return False

        # First command must be between zero and max 
        if self.FirstCommand < 0 or self.FirstCommand > max_history:
            return False

        # Validate first command with last added 
        if self.FirstCommand != 0 and self.FirstCommand != self.LastAdded + 1:
            return False

        # Process handle must be a valid pid 
        if self.ProcessHandle <= 0 or self.ProcessHandle > 0xFFFF:
            return False

        Popup = obj.Object("_POPUP_LIST", offset = self.PopupList.Flink,
            vm = self.obj_vm)

        # Check that the popup list entry is in tact
        if Popup.ListEntry.Blink != self.PopupList.obj_offset:
            return False

        return True

    def get_commands(self):
        """Generator for commands in the history buffer. 

        The CommandBucket is an array of pointers to _COMMAND 
        structures. The array size is CommandCount. Once CommandCount 
        is reached, the oldest commands are cycled out and the 
        rest are coalesced. 
        """
        for i, cmd in enumerate(self.CommandBucket):
            if cmd:
                yield i, cmd.dereference()

#--------------------------------------------------------------------------------
# Profile Modifications 
#--------------------------------------------------------------------------------

class CmdHistoryVTypesx86(obj.ProfileModification):
    """This modification applies the vtypes for 32bit 
    Windows up to Windows 7."""

    before = ['WindowsObjectClasses']

    def check(self, profile):
        m = profile.metadata
        return (m.get('os', None) == 'windows' and
                m.get('memory_model', '32bit') == '32bit' and
                (m.get('major') < 6 or (m.get('major') == 6 and m.get('minor') < 1)))

    def modification(self, profile):
        profile.vtypes.update(winsrv_types_x86)

class CmdHistoryVTypesx64(obj.ProfileModification):
    """This modification applies the vtypes for 64bit 
    Windows up to Windows 7."""

    before = ['WindowsObjectClasses']

    def check(self, profile):
        m = profile.metadata
        return (m.get('os', None) == 'windows' and
                m.get('memory_model', '32bit') == '64bit' and
                (m.get('major') < 6 or (m.get('major') == 6 and m.get('minor') < 1)))

    def modification(self, profile):
        profile.vtypes.update(winsrv_types_x64)

class CmdHistoryVTypesWin7x86(obj.ProfileModification):
    """This modification applies the vtypes for 32bit 
    Windows starting with Windows 7."""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 1,
                  'memory_model': lambda x : x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(conhost_types_x86)

class CmdHistoryVTypesWin7x64(obj.ProfileModification):
    """This modification applies the vtypes for 64bit 
    Windows starting with Windows 7."""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 1,
                  'memory_model': lambda x : x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(conhost_types_x64)

class CmdHistoryObjectClasses(obj.ProfileModification):
    """This modification applies the object classes for all 
    versions of 32bit Windows."""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows'}
                 # 'memory_model': lambda x : x == '32bit'}
    def modification(self, profile):
        profile.object_classes.update({
            '_CONSOLE_INFORMATION': _CONSOLE_INFORMATION,
            '_SCREEN_INFORMATION': _SCREEN_INFORMATION,
            '_EXE_ALIAS_LIST': _EXE_ALIAS_LIST,
            '_COMMAND_HISTORY': _COMMAND_HISTORY,
            '_CONSOLE_PROCESS': _CONSOLE_PROCESS,
        })

#--------------------------------------------------------------------------------
# CmdScan Plugin 
#--------------------------------------------------------------------------------

class CmdScan(common.AbstractWindowsCommand):
    """Extract command history by scanning for _COMMAND_HISTORY"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        # The default comes from HKCU\Console\HistoryBufferSize
        config.add_option('MAX_HISTORY', short_option = 'M', default = MAX_HISTORY_DEFAULT,
                            action = 'store', type = 'int',
                            help = 'CommandCountMax (default = 50)')

    def cmdhistory_process_filter(self, addr_space):
        """Generator for processes that might contain command 
        history information. 

        Takes into account if we're on Windows 7 or an earlier
        operator system. 

        @param addr_space: a kernel address space. 
        """

        # Detect if we're on windows seven 
        use_conhost = (6, 1) <= (addr_space.profile.metadata.get('major', 0),
                                addr_space.profile.metadata.get('minor', 0))

        for task in tasks.pslist(addr_space):
            process_name = str(task.ImageFileName).lower()
            # The process we select is conhost on Win7 or csrss for others
            if ((use_conhost and process_name == "conhost.exe") or
                        (not use_conhost and process_name == "csrss.exe")):
                yield task

    def calculate(self):
        """The default pattern we search for, as described by Stevens and Casey, 
        is "\x32\x00". That's because CommandCountMax is a little-endian 
        unsigned short whose default value is 50. However, that value can be 
        changed by right clicking cmd.exe and going to Properties->Options->Cmd History 
        or by calling the API function kernel32!SetConsoleHistoryInfo. Thus 
        you can tweak the search criteria by using the --MAX_HISTORY. 
        """

        addr_space = utils.load_as(self._config)

        MAX_HISTORY = self._config.MAX_HISTORY
        srch_pattern = chr(MAX_HISTORY) + "\x00"

        for task in self.cmdhistory_process_filter(addr_space):
            process_space = task.get_process_address_space()
            for found in task.search_process_memory([srch_pattern], vad_filter = lambda x: x.Length < 0x40000000):

                hist = obj.Object("_COMMAND_HISTORY",
                        vm = process_space,
                        offset = found - addr_space.profile.\
                        get_obj_offset("_COMMAND_HISTORY", "CommandCountMax"))

                if hist.is_valid(max_history = MAX_HISTORY):
                    yield task, hist

    def unified_output(self, data):
        return TreeGrid([("Process", str),
                         ("PID", int),
                         ("History Offset", Address),
                         ("Application", str),
                         ("Flags", str),
                         ("Command Count", int),
                         ("Last Added", str),
                         ("Last Displayed", str),
                         ("First Command", str),
                         ("Command Count Max", int),
                         ("Handle", int),
                         ("Command Number", int),
                         ("Command Offset", Address),
                         ("Command", str)],
                        self.generator(data))

    def generator(self, data):

        for task, hist in data:

            # If the _COMMAND_HISTORY is in use, we would only take 
            # hist.CommandCount but since we're brute forcing, try the 
            # maximum and hope that some slots were not overwritten 
            # or zero-ed out. 
            pointers = obj.Object("Array", targetType = "address",
                        count = hist.CommandCountMax,
                        offset = hist.obj_offset +
                        hist.obj_vm.profile.get_obj_offset("_COMMAND_HISTORY", "CommandBucket"),
                        vm = hist.obj_vm)

            values = [  str(task.ImageFileName),
                        int(task.UniqueProcessId),
                        Address(hist.obj_offset),
                        str(hist.Application.dereference()),
                        str(hist.Flags),
                        int(hist.CommandCount),
                        str(hist.LastAdded),
                        str(hist.LastDisplayed),
                        str(hist.FirstCommand),
                        int(hist.CommandCountMax),
                        int(hist.ProcessHandle),
                     ]

            for i, p in enumerate(pointers):
                cmd = p.dereference_as("_COMMAND")
                if cmd and str(cmd.Cmd):
                    yield (0, values + [
                                    int(i),
                                    Address(cmd.obj_offset),
                                    str(cmd.Cmd) ])


    def render_text(self, outfd, data):

        for task, hist in data:

            outfd.write("*" * 50 + "\n")
            outfd.write("CommandProcess: {0} Pid: {1}\n".format(
                task.ImageFileName, task.UniqueProcessId))
            outfd.write("CommandHistory: {0:#x} Application: {1} Flags: {2}\n".format(
                hist.obj_offset, hist.Application.dereference(),
                hist.Flags))
            outfd.write("CommandCount: {0} LastAdded: {1} LastDisplayed: {2}\n".format(
                hist.CommandCount, hist.LastAdded, hist.LastDisplayed))
            outfd.write("FirstCommand: {0} CommandCountMax: {1}\n".format(
                hist.FirstCommand, hist.CommandCountMax))
            outfd.write("ProcessHandle: {0:#x}\n".format(hist.ProcessHandle))

            # If the _COMMAND_HISTORY is in use, we would only take 
            # hist.CommandCount but since we're brute forcing, try the 
            # maximum and hope that some slots were not overwritten 
            # or zero-ed out. 
            pointers = obj.Object("Array", targetType = "address",
                        count = hist.CommandCountMax,
                        offset = hist.obj_offset +
                        hist.obj_vm.profile.get_obj_offset("_COMMAND_HISTORY", "CommandBucket"),
                        vm = hist.obj_vm)

            for i, p in enumerate(pointers):
                cmd = p.dereference_as("_COMMAND")
                if cmd and str(cmd.Cmd):
                    outfd.write("Cmd #{0} @ {1:#x}: {2}\n".format(
                        i, cmd.obj_offset, str(cmd.Cmd)))

#--------------------------------------------------------------------------------
# Consoles Plugin 
#--------------------------------------------------------------------------------

class Consoles(CmdScan):
    """Extract command history by scanning for _CONSOLE_INFORMATION"""

    def __init__(self, config, *args, **kwargs):
        CmdScan.__init__(self, config, *args, **kwargs)
        # The default comes from HKCU\Console\NumberOfHistoryBuffers
        config.add_option('HISTORY_BUFFERS', short_option = 'B', default = 4,
                            action = 'store', type = 'int',
                            help = 'HistoryBufferMax (default = 4)')

    def calculate(self):
        addr_space = utils.load_as(self._config)

        srch_pattern = chr(self._config.MAX_HISTORY) + "\x00"

        for task in self.cmdhistory_process_filter(addr_space):
            for found in task.search_process_memory([srch_pattern], vad_filter = lambda x: x.Length < 0x40000000):

                console = obj.Object("_CONSOLE_INFORMATION",
                    offset = found -
                    addr_space.profile.get_obj_offset("_CONSOLE_INFORMATION", "CommandHistorySize"),
                    vm = task.get_process_address_space(),
                    parent = task)

                if (console.HistoryBufferMax != self._config.HISTORY_BUFFERS or
                    console.HistoryBufferCount > self._config.HISTORY_BUFFERS):
                    continue

                # Check the first command history as the final constraint 
                history = obj.Object("_COMMAND_HISTORY",
                    offset = console.HistoryList.Flink.dereference().obj_offset -
                    addr_space.profile.get_obj_offset("_COMMAND_HISTORY", "ListEntry"),
                    vm = task.get_process_address_space())

                if history.CommandCountMax != self._config.MAX_HISTORY:
                    continue

                yield task, console

    def unified_output(self, data):
        return TreeGrid([('Console Process', str),
                         ('Console PID', int),
                         ('Console ID', int),
                         ('Command History Size', int),
                         ('History Buffer Count', int),
                         ('History Buffer Max', int),
                         ('OriginalTitle', str),
                         ('Title', str),
                         ('Attached Process Name', str),
                         ('Attached Process PID', int),
                         ('Attached Process Handle', int),
                         ('Command History ID', int),
                         ('Command History Applications', str),
                         ('Command History Flags', str),
                         ('Command History Count', int),
                         ('Command History Last Added', str),
                         ('Command History Last Displayed', str),
                         ('Command History First Command', str),
                         ('Command History Command Count Max', int),
                         ('Command History Process Handle', int),
                         ('Command History Command Number', int),
                         ('Command History Command Offset', Address),
                         ('Command History Command String', str),
                         ('EXE Alias', str),
                         ('EXE Alias Source', str),
                         ('EXE Alias Target', str),
                         ('Screen ID', str),
                         ('Screen X', int),
                         ('Screen Y', int),
                         ('Screen Dump', str)],
                        self.generator(data))

    def _get_values(self, task, console, process=None, console_proc=None,
                    hist=None, hist_i=None, hist_cmd=None, exe_alias=None,
                    screen=None):

        # ('Console Process', str),
        # ('Console PID', int),
        # ('Console ID', int),
        # ('Command History Size', int),
        # ('History Buffer Count', int),
        # ('History Buffer Max', int),
        # ('OriginalTitle', str),
        # ('Title', str),
        v = [ str(task.ImageFileName),
                 int(task.UniqueProcessId),
                 int(console.obj_offset),
                 int(console.CommandHistorySize),
                 int(console.HistoryBufferCount),
                 int(console.HistoryBufferMax),
                 str(console.OriginalTitle.dereference()),
                 str(console.Title.dereference()) ]

        # ('Attached Process Name', str),
        # ('Attached Process PID', int),
        # ('Attached Process Handle', int),
        if process is not None and console_proc is not None:
            v.extend([ str(process.ImageFileName),
                          int(process.UniqueProcessId),
                          int(console_proc.ProcessHandle) ])
        else:
            v.extend([ "", -1, -1 ])

        # ('Command History ID', int),
        # ('Command History Applications', str),
        # ('Command History Flags', str),
        # ('Command History Count', int),
        # ('Command History Last Added', str),
        # ('Command History Last Displayed', str),
        # ('Command History First Command', str),
        # ('Command History Command Count Max', int),
        # ('Command History Process Handle', int),
        # ('Command History Command Number', int),
        # ('Command History Command Offset', Address),
        # ('Command History Command String', str),
        if hist is not None:
            v.extend([
                int(hist.obj_offset),
                str(hist.Application.dereference()),
                str(hist.Flags),
                int(hist.CommandCount),
                str(hist.LastAdded),
                str(hist.LastDisplayed),
                str(hist.FirstCommand),
                int(hist.CommandCountMax),
                int(hist.ProcessHandle) ])
            if hist_i is None or hist_cmd is None:
                v.extend([ -1, Address(-1), '' ])
            else:
                v.extend([
                    int(hist_i),
                    Address(hist_cmd.obj_offset),
                    str(hist_cmd.Cmd) ])
        else:
            v.extend([
                -1,
                '',
                '',
                -1,
                '',
                '',
                '',
                -1,
                -1,
                -1,
                Address(-1),
                '' ])

        # ('EXE Alias', str),
        # ('EXE Alias Source', str),
        # ('EXE Alias Target', str),
        if exe_alias is not None:
            v.extend([
                str(exe_alias.ExeName.dereference()),
                str(alias.Source.dereference()),
                str(alias.Target.dereference()) ])
        else:
            v.extend([ '', '', '' ])

        # ('Screen ID', str),
        # ('Screen X', int),
        # ('Screen Y', int),
        # ('Screen Dump', str)],
        if screen is not None:
            v.extend([
                str(screen.dereference()),
                int(screen.ScreenX),
                int(screen.ScreenY),
                '\n'.join(screen.get_buffer()) ])
        else:
            v.extend([ '', -1, -1, '' ])

        return v

    def generator(self, data):

        for task, console in data:

            has_yielded = False

            for console_proc in console.get_processes():
                process = console_proc.reference_object_by_handle()
                if process:
                    has_yielded = True
                    yield (0, self._get_values(task, console, process=process,
                        console_proc=console_proc))

            for hist in console.get_histories():
                cmds_processed = False
                for i, cmd in hist.get_commands():
                    if cmd.Cmd:
                        cmds_processed = True
                        yield (0, self._get_values(task, console, hist=hist,
                                hist_i=i, hist_cmd=cmd ))
                    has_yielded = cmds_processed
                if not cmds_processed:
                    # Did not generate any commands, so generate basic history
                    # information so that no information is dropped.
                    has_yielded = True
                    yield (0, self._get_values(task, console, hist=hist))

            for exe_alias in console.get_exe_aliases():
                for alias in exe_alias.get_aliases():
                    has_yielded = True
                    yield (0, self._get_values(task, console, exe_alias=alias))

            for screen in console.get_screens():
                has_yielded = True
                yield (0, self._get_values(task, console, screen=screen))

            # if we have not yet generated any information
            if not has_yielded:
                # generate at least basic console information
                yield (0, self._get_values(task, console))


    def render_text(self, outfd, data):

        for task, console in data:

            outfd.write("*" * 50 + "\n")
            outfd.write("ConsoleProcess: {0} Pid: {1}\n".format(
                task.ImageFileName, task.UniqueProcessId))
            outfd.write("Console: {0:#x} CommandHistorySize: {1}\n".format(
                console.obj_offset, console.CommandHistorySize))
            outfd.write("HistoryBufferCount: {0} HistoryBufferMax: {1}\n".format(
                console.HistoryBufferCount, console.HistoryBufferMax))
            outfd.write("OriginalTitle: {0}\n".format(console.OriginalTitle.dereference()))
            outfd.write("Title: {0}\n".format(console.Title.dereference()))

            for console_proc in console.get_processes():
                process = console_proc.reference_object_by_handle()
                if process:
                    outfd.write("AttachedProcess: {0} Pid: {1} Handle: {2:#x}\n".format(
                        process.ImageFileName, process.UniqueProcessId,
                        console_proc.ProcessHandle))

            for hist in console.get_histories():
                outfd.write("----\n")
                outfd.write("CommandHistory: {0:#x} Application: {1} Flags: {2}\n".format(
                    hist.obj_offset, hist.Application.dereference(),
                    hist.Flags))
                outfd.write("CommandCount: {0} LastAdded: {1} LastDisplayed: {2}\n".format(
                    hist.CommandCount, hist.LastAdded, hist.LastDisplayed))
                outfd.write("FirstCommand: {0} CommandCountMax: {1}\n".format(
                    hist.FirstCommand, hist.CommandCountMax))
                outfd.write("ProcessHandle: {0:#x}\n".format(hist.ProcessHandle))
                for i, cmd in hist.get_commands():
                    if cmd.Cmd:
                        outfd.write("Cmd #{0} at {1:#x}: {2}\n".format(
                            i, cmd.obj_offset, str(cmd.Cmd)))

            for exe_alias in console.get_exe_aliases():
                for alias in exe_alias.get_aliases():
                    outfd.write("----\n")
                    outfd.write("Alias: {0} Source: {1} Target: {2}\n".format(
                        exe_alias.ExeName.dereference(), alias.Source.dereference(),
                        alias.Target.dereference()))

            for screen in console.get_screens():
                outfd.write("----\n")
                outfd.write("Screen {0:#x} X:{1} Y:{2}\n".format(
                    screen.dereference(), screen.ScreenX, screen.ScreenY))
                outfd.write("Dump:\n{0}\n".format('\n'.join(screen.get_buffer())))
