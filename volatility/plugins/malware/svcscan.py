# Volatility
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
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

import volatility.utils as utils 
import volatility.obj as obj
import volatility.debug as debug
import volatility.commands as commands
import volatility.win32.tasks as tasks

#--------------------------------------------------------------------------------
# vtypes
#--------------------------------------------------------------------------------

svcscan_legacy_types_x86 = {
    '_SERVICE_LIST_ENTRY' : [ 0x8, {
    'Blink' : [ 0x0, ['pointer', ['_SERVICE_RECORD']]],
    'Flink' : [ 0x4, ['pointer', ['_SERVICE_RECORD']]],
    } ],
    '_SERVICE_RECORD' : [ None, {
    'ServiceList' : [ 0x0, ['_SERVICE_LIST_ENTRY']],
    'ServiceName' : [ 0x8, ['pointer', ['String', dict(encoding = 'utf16', length = 512)]]],
    'DisplayName' : [ 0xc, ['pointer', ['String', dict(encoding = 'utf16', length = 512)]]],
    'Order' : [ 0x10, ['unsigned int']],
    'Tag' : [ 0x18, ['array', 4, ['unsigned char']]], 
    'DriverName' : [ 0x24, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'ServiceProcess' : [ 0x24, ['pointer', ['_SERVICE_PROCESS']]],
    'Type' : [ 0x28, ['Flags', {'bitmap': {
            'SERVICE_KERNEL_DRIVER': 0, 
            'SERVICE_FILE_SYSTEM_DRIVER': 1, 
            'SERVICE_WIN32_OWN_PROCESS': 4, 
            'SERVICE_WIN32_SHARE_PROCESS': 5, 
            'SERVICE_INTERACTIVE_PROCESS': 8}}]],
    'State' : [ 0x2c, ['Enumeration', dict(target = 'long', choices = {
            1: 'SERVICE_STOPPED',
            2: 'SERVICE_START_PENDING', 
            3: 'SERVICE_STOP_PENDING', 
            4: 'SERVICE_RUNNING', 
            5: 'SERVICE_CONTINUE_PENDING', 
            6: 'SERVICE_PAUSE_PENDING', 
            7: 'SERVICE_PAUSED'})]],
    } ],
    '_SERVICE_PROCESS' : [ None, {
    'BinaryPath' : [ 0x8, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'ProcessId' : [ 0xc, ['unsigned int']],
    } ],
}

svcscan_legacy_types_x64 = {
    '_SERVICE_LIST_ENTRY' : [ 0x8, {
    'Blink' : [ 0x0, ['pointer', ['_SERVICE_RECORD']]],
    'Flink' : [ 0x10, ['pointer', ['_SERVICE_RECORD']]],
    } ],
    '_SERVICE_RECORD' : [ None, {
    'ServiceList' : [ 0x0, ['_SERVICE_LIST_ENTRY']],
    'ServiceName' : [ 0x8, ['pointer', ['String', dict(encoding = 'utf16', length = 512)]]], 
    'DisplayName' : [ 0x10, ['pointer', ['String', dict(encoding = 'utf16', length = 512)]]], 
    'Order' : [ 0x18, ['unsigned int']], 
    'Tag' : [ 0x20, ['array', 4, ['unsigned char']]], 
    'DriverName' : [ 0x30, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'ServiceProcess' : [ 0x30, ['pointer', ['_SERVICE_PROCESS']]],
    'Type' : [ 0x38, ['Flags', {'bitmap': { 
            'SERVICE_KERNEL_DRIVER': 0, 
            'SERVICE_FILE_SYSTEM_DRIVER': 1, 
            'SERVICE_WIN32_OWN_PROCESS': 4, 
            'SERVICE_WIN32_SHARE_PROCESS': 5, 
            'SERVICE_INTERACTIVE_PROCESS': 8}}]],
    'State' : [ 0x3C, ['Enumeration', dict(target = 'long', choices = { 
            1: 'SERVICE_STOPPED',
            2: 'SERVICE_START_PENDING', 
            3: 'SERVICE_STOP_PENDING', 
            4: 'SERVICE_RUNNING', 
            5: 'SERVICE_CONTINUE_PENDING', 
            6: 'SERVICE_PAUSE_PENDING', 
            7: 'SERVICE_PAUSED'})]],
    } ],
    '_SERVICE_PROCESS': [ None, {
    'BinaryPath': [ 0x10, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]], 
    'ProcessId': [ 0x18, ['unsigned int']], 
    } ],
}

svcscan_recent_types_x86 = {
    '_SERVICE_HEADER': [ None, {
    'Tag': [ 0x0, ['array', 4, ['unsigned char']]], 
    'ServiceRecord': [ 0xC, ['pointer', ['_SERVICE_RECORD']]], 
    } ],
    '_SERVICE_RECORD': [ None, {
    'PrevEntry': [ 0x0, ['pointer', ['_SERVICE_RECORD']]], 
    'ServiceName': [ 0x4, ['pointer', ['String', dict(encoding = 'utf16', length = 512)]]],
    'DisplayName': [ 0x8, ['pointer', ['String', dict(encoding = 'utf16', length = 512)]]],
    'Order': [ 0xC, ['unsigned int']], 
    'ServiceProcess': [ 0x1C, ['pointer', ['_SERVICE_PROCESS']]], 
    'DriverName': [ 0x1C, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'Type' : [ 0x20, ['Flags', {'bitmap': {
            'SERVICE_KERNEL_DRIVER': 0, 
            'SERVICE_FILE_SYSTEM_DRIVER': 1, 
            'SERVICE_WIN32_OWN_PROCESS': 4, 
            'SERVICE_WIN32_SHARE_PROCESS': 5, 
            'SERVICE_INTERACTIVE_PROCESS': 8}}]],
    'State': [ 0x24, ['Enumeration', dict(target = 'long', choices = {
            1: 'SERVICE_STOPPED', 
            2: 'SERVICE_START_PENDING', 
            3: 'SERVICE_STOP_PENDING', 
            4: 'SERVICE_RUNNING', 
            5: 'SERVICE_CONTINUE_PENDING', 
            6: 'SERVICE_PAUSE_PENDING', 
            7: 'SERVICE_PAUSED'})]],
    } ],
    '_SERVICE_PROCESS': [ None, {
    'BinaryPath': [ 0x8, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]], 
    'ProcessId': [ 0xC, ['unsigned int']], 
    } ],
}

svcscan_recent_types_x64 = {
    '_SERVICE_HEADER': [ None, {
    'Tag': [ 0x0, ['array', 4, ['unsigned char']]], 
    'ServiceRecord': [ 0x10, ['pointer', ['_SERVICE_RECORD']]], 
    } ],
    '_SERVICE_RECORD': [ None, {
    'PrevEntry': [ 0x0, ['pointer', ['_SERVICE_RECORD']]], 
    'ServiceName': [ 0x8, ['pointer', ['String', dict(encoding = 'utf16', length = 512)]]], 
    'DisplayName': [ 0x10, ['pointer', ['String', dict(encoding = 'utf16', length = 512)]]], 
    'Order': [ 0x18, ['unsigned int']],  
    'ServiceProcess': [ 0x28, ['pointer', ['_SERVICE_PROCESS']]],
    'DriverName': [ 0x28, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]],
    'Type' : [ 0x30, ['Flags', {'bitmap': { 
            'SERVICE_KERNEL_DRIVER': 0, 
            'SERVICE_FILE_SYSTEM_DRIVER': 1, 
            'SERVICE_WIN32_OWN_PROCESS': 4, 
            'SERVICE_WIN32_SHARE_PROCESS': 5, 
            'SERVICE_INTERACTIVE_PROCESS': 8}}]],
    'State': [ 0x34, ['Enumeration', dict(target = 'long', choices = { 
            1: 'SERVICE_STOPPED', 
            2: 'SERVICE_START_PENDING', 
            3: 'SERVICE_STOP_PENDING', 
            4: 'SERVICE_RUNNING', 
            5: 'SERVICE_CONTINUE_PENDING', 
            6: 'SERVICE_PAUSE_PENDING', 
            7: 'SERVICE_PAUSED'})]],
    } ],
    '_SERVICE_PROCESS': [ None, {
    'BinaryPath': [ 0x10, ['pointer', ['String', dict(encoding = 'utf16', length = 256)]]], 
    'ProcessId': [ 0x18, ['unsigned int']], 
    } ],
}

#--------------------------------------------------------------------------------
# object classes 
#--------------------------------------------------------------------------------

class _SERVICE_RECORD_LEGACY(obj.CType):
    "Service records for XP/2003 x86 and x64"

    @property
    def Binary(self):
        "Return the binary path for a service"

        # No path in memory for services that aren't running
        # (if needed, query the registry key)
        if str(self.State) != 'SERVICE_RUNNING':
            return obj.NoneObject("No path, service isn't running")

        # Depending on whether the service is for a process 
        # or kernel driver, the binary path is stored differently
        if 'PROCESS' in str(self.Type): 
            return self.ServiceProcess.BinaryPath.dereference()
        else:
            return self.DriverName.dereference() 

    @property
    def Pid(self):
        "Return the process ID for a service"

        if str(self.State) == 'SERVICE_RUNNING':
            if 'PROCESS' in str(self.Type): 
                return self.ServiceProcess.ProcessId

        return obj.NoneObject("Cannot get process ID")

    def is_valid(self):
        "Check some fields for validity"
        return obj.CType.is_valid(self) and self.Order > 0 and self.Order < 0xFFFF 

class _SERVICE_RECORD_RECENT(_SERVICE_RECORD_LEGACY):
    "Service records for 2008, Vista, 7 x86 and x64"

    def traverse(self):
        """Generator that walks the singly-linked list"""

        yield self # Include this object in the list 
        rec = self.PrevEntry
        while rec and rec.is_valid():
            yield rec        
            rec = rec.PrevEntry

class _SERVICE_HEADER(obj.CType):
    "Service headers for 2008, Vista, 7 x86 and x64"

    def is_valid(self):
        "Check some fields for validity"
        return (obj.CType.is_valid(self) and 
                    self.ServiceRecord.is_valid() and 
                    self.ServiceRecord.Order < 0xFFFF)

#--------------------------------------------------------------------------------
# profile modifications 
#--------------------------------------------------------------------------------

class MalwareSvcLegacy(obj.ProfileModification):
    """Service record object class for XP/2003 x86 and x64"""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows', 
                  'major': lambda x: x == 5, 
                  'minor': lambda x: x >= 1}
    def modification(self, profile):
        profile.object_classes.update({
            '_SERVICE_RECORD': _SERVICE_RECORD_LEGACY,
            })
        profile.merge_overlay({'VOLATILITY_MAGIC': [ None, {
            'ServiceTag': [ 0x0, ['VolatilityMagic', dict(value = "sErv")]]
            }]})

class MalwareSvcLegacyVTypesx86(obj.ProfileModification):
    """Service vtypes for XP/2003 x86"""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows', 
                  'major': lambda x: x == 5, 
                  'minor': lambda x: x >= 1, 
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(svcscan_legacy_types_x86)

class MalwareSvcLegacyVTypesx64(obj.ProfileModification):
    """Service vtypes for XP/2003 x64"""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows', 
                  'major': lambda x: x == 5, 
                  'minor': lambda x: x >= 1, 
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(svcscan_legacy_types_x64)

class MalwareSvcRecent(obj.ProfileModification):
    """Service object classes for Vista, 2008, and 7 x86 and x64"""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows', 
                  'major': lambda x: x >= 6}
    def modification(self, profile):
        profile.object_classes.update({
            '_SERVICE_RECORD': _SERVICE_RECORD_RECENT,
            '_SERVICE_HEADER': _SERVICE_HEADER,
        })
        profile.merge_overlay({'VOLATILITY_MAGIC': [ None, {
            'ServiceTag': [ 0x0, ['VolatilityMagic', dict(value = "serH")]]
            }]})

class MalwareSvcRecentVTypesx86(obj.ProfileModification):
    """Service vtypes for Vista, 2008, and 7 x86"""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows', 
                  'major': lambda x: x >= 6, 
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(svcscan_recent_types_x86)

class MalwareSvcRecentVTypesx64(obj.ProfileModification):
    """Service vtypes for Vista, 2008, and 7 x64"""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows', 
                  'major': lambda x: x >= 6, 
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(svcscan_recent_types_x64)

#--------------------------------------------------------------------------------
# svcscan plugin 
#--------------------------------------------------------------------------------

class SvcScan(commands.Command):
    "Scan for Windows services"

    def calculate(self):
        addr_space = utils.load_as(self._config)

        # Get the version we're analyzing 
        version = (addr_space.profile.metadata.get('major', 0), 
                   addr_space.profile.metadata.get('minor', 0))

        tag = obj.VolMagic(addr_space).ServiceTag.v()        

        # On systems more recent than XP/2003, the serH marker doesn't
        # find *all* services, but the ones it does find have linked
        # lists to the others. We use this variable to track which
        # ones we've seen so as to not yield duplicates. 
        records = []

        for task in tasks.pslist(addr_space):
            # We only want the Service Control Manager process
            if str(task.ImageFileName).lower() != "services.exe":
                continue
            # Process AS must be valid 
            process_space = task.get_process_address_space()
            if process_space == None:
                continue 
            # Find all instances of the record tag 
            for address in task.search_process_memory(tag):
                if version <= (5,2):
                    # Windows XP/2003 
                    rec = obj.Object("_SERVICE_RECORD", offset = address - 
                            addr_space.profile.get_obj_offset('_SERVICE_RECORD', 'Tag'), 
                            vm = process_space
                            )
                    # Apply our sanity checks
                    if rec.is_valid():
                        yield rec 
                else:
                    # Windows Vista, 2008, and 7
                    svc_hdr = obj.Object('_SERVICE_HEADER', offset = address, 
                            vm = process_space)
                    # Apply our sanity checks
                    if svc_hdr.is_valid():
                        # Since we walk the s-list backwards, if we've seen 
                        # an object, then we've also seen all objects that 
                        # exist before it, thus we can break at that time. 
                        for rec in svc_hdr.ServiceRecord.traverse():
                            if rec in records:
                                break
                            records.append(rec)
                            yield rec

    def render_text(self, outfd, data):

        for rec in data:
            # This can't possibly look neat in a table with columns...
            outfd.write("Offset: {0:#x}\n".format(rec.obj_offset))
            outfd.write("Order: {0}\n".format(rec.Order))
            outfd.write("Process ID: {0}\n".format(rec.Pid))
            outfd.write("Service Name: {0}\n".format(rec.ServiceName.dereference()))
            outfd.write("Display Name: {0}\n".format(rec.DisplayName.dereference()))
            outfd.write("Service Type: {0}\n".format(rec.Type))
            outfd.write("Service State: {0}\n".format(rec.State))
            outfd.write("Binary Path: {0}\n".format(rec.Binary))
            outfd.write("\n")
