# Volatility
# Copyright (c) 2008-2015 Volatility Foundation
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

"""
@author:       The Volatility Foundation
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net

This file provides support for Windows 10.
"""

import volatility.plugins.overlays.windows.windows as windows
import volatility.obj as obj
import volatility.win32.tasks as tasks 
import volatility.debug as debug
import volatility.plugins.overlays.windows.win8 as win8

try:
    import distorm3
    has_distorm = True
except ImportError:
    has_distorm = False

class _HMAP_ENTRY(obj.CType):

    @property
    def BlockAddress(self):
        return self.PermanentBinAddress & 0xFFFFFFFFFFF0

class Win10Registry(obj.ProfileModification):
    """The Windows 10 registry HMAP"""

    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4}

    def modification(self, profile):
        profile.object_classes.update({"_HMAP_ENTRY": _HMAP_ENTRY})

class Win10x64DTB(obj.ProfileModification):
    """The Windows 10 64-bit DTB signature"""

    before = ['WindowsOverlay', 'Windows64Overlay', 'Win8x64DTB']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'memory_model': lambda x: x == '64bit',
                  }

    def modification(self, profile):
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\xb6\x00")]],
            }]})

class Win10x86DTB(obj.ProfileModification):
    """The Windows 10 32-bit DTB signature"""

    before = ['WindowsOverlay', 'Win8x86DTB']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'memory_model': lambda x: x == '32bit',
                  }

    def modification(self, profile):
        build = profile.metadata.get("build", 0)

        if build >= 15063:
            signature = "\x03\x00\x2C\x00"
        else:
            signature = "\x03\x00\x2A\x00"

        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'DTBSignature' : [ None, ['VolatilityMagic', dict(value = signature)]],
            }]})

class Win10KDBG(windows.AbstractKDBGMod):
    """The Windows 10 KDBG signatures"""

    before = ['Win8KDBG']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x >= 14393}

    kdbgsize = 0x368

class ObHeaderCookieStore(object):
    """A class for finding and storing the nt!ObHeaderCookie value"""

    _instance = None

    def __init__(self):
        self._cookie = None

    def cookie(self):
        return self._cookie 

    def findcookie(self, kernel_space):
        """Find and read the nt!ObHeaderCookie value. 

        On success, return True and save the cookie value in self._cookie.
        On Failure, return False. 

        This method must be called before performing any tasks that require 
        object header validation including handles, psxview (due to pspcid) 
        and the object scanning plugins (psscan, etc). 

        NOTE: this cannot be implemented as a volatility "magic" class,
        because it must be persistent across various classes and sources. 
        We don't want to recalculate the cookie value multiple times. 
        """

        meta = kernel_space.profile.metadata 
        vers = (meta.get("major", 0), meta.get("minor", 0))

        # this algorithm only applies to Windows 10 or greater 
        if vers < (6, 4):
            return True 

        # prevent subsequent attempts from recalculating the existing value 
        if self._cookie:
            return True

        if not has_distorm:
            debug.warning("distorm3 module is not installed")
            return False 

        kdbg = tasks.get_kdbg(kernel_space)
        
        if not kdbg:
            debug.warning("Cannot find KDBG")
            return False
        
        nt_mod = None 
        
        for mod in kdbg.modules():
            nt_mod = mod 
            break 
            
        if nt_mod == None:
            debug.warning("Cannot find NT module")
            return False

        addr = nt_mod.getprocaddress("ObGetObjectType")
        if addr == None:
            debug.warning("Cannot find nt!ObGetObjectType")
            return False 

        # produce an absolute address by adding the DLL base to the RVA 
        addr += nt_mod.DllBase 
        if not nt_mod.obj_vm.is_valid_address(addr):
            debug.warning("nt!ObGetObjectType at {0} is invalid".format(addr))
            return False 

        # in theory...but so far we haven't tested 32-bits 
        model = meta.get("memory_model")    
        if model == "32bit":
            mode = distorm3.Decode32Bits
        else:
            mode = distorm3.Decode64Bits

        data = nt_mod.obj_vm.read(addr, 100)
        ops = distorm3.Decompose(addr, data, mode, distorm3.DF_STOP_ON_RET)
        addr = None

        # search backwards from the RET and find the MOVZX 

        if model == "32bit":
            # movzx ecx, byte ptr ds:_ObHeaderCookie
            for op in reversed(ops):
                if (op.size == 7 and 
                            'FLAG_DST_WR' in op.flags and
                            len(op.operands) == 2 and 
                            op.operands[0].type == 'Register' and 
                            op.operands[1].type == 'AbsoluteMemoryAddress' and 
                            op.operands[1].size == 8):
                    addr = op.operands[1].disp & 0xFFFFFFFF
                    break
        else:
            # movzx ecx, byte ptr cs:ObHeaderCookie 
            for op in reversed(ops):
                if (op.size == 7 and 
                            'FLAG_RIP_RELATIVE' in op.flags and
                            len(op.operands) == 2 and 
                            op.operands[0].type == 'Register' and 
                            op.operands[1].type == 'AbsoluteMemory' and 
                            op.operands[1].size == 8):
                    addr = op.address + op.size + op.operands[1].disp 
                    break

        if not addr:
            debug.warning("Cannot find nt!ObHeaderCookie")
            return False

        if not nt_mod.obj_vm.is_valid_address(addr):
            debug.warning("nt!ObHeaderCookie at {0} is not valid".format(addr))
            return False

        cookie = obj.Object("unsigned int", offset = addr, vm = nt_mod.obj_vm)
        self._cookie = int(cookie)

        return True

    @staticmethod
    def instance():
        if not ObHeaderCookieStore._instance:
            ObHeaderCookieStore._instance = ObHeaderCookieStore()

        return ObHeaderCookieStore._instance 

class VolatilityCookie(obj.VolatilityMagic):
    """The Windows 10 Cookie Finder"""

    def v(self):
        if self.value is None:
            return self.get_best_suggestion()
        else:
            return self.value

    def get_suggestions(self):
        if self.value:
            yield self.value
        for x in self.generate_suggestions():
            yield x

    def generate_suggestions(self):
        store = ObHeaderCookieStore.instance()
        store.findcookie(self.obj_vm)
        yield store.cookie()

class Win10Cookie(obj.ProfileModification):
    """The Windows 10 Cookie Finder"""

    before = ['WindowsOverlay']

    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  }

    def modification(self, profile):
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'ObHeaderCookie' : [ 0x0, ['VolatilityCookie', dict(configname = "COOKIE")]],
            }]})
        profile.object_classes.update({'VolatilityCookie': VolatilityCookie})

class _OBJECT_HEADER_10(win8._OBJECT_HEADER):
        
    @property
    def TypeIndex(self):
        """Wrap the TypeIndex member with a property that decodes it 
        with the nt!ObHeaderCookie value."""

        cook = obj.VolMagic(self.obj_vm).ObHeaderCookie.v()
        addr = self.obj_offset 
        indx = int(self.m("TypeIndex"))

        return ((addr >> 8) ^ cook ^ indx) & 0xFF

    def is_valid(self):
        """Determine if a given object header is valid"""

        if not obj.CType.is_valid(self):
            return False

        if self.InfoMask > 0x88:
            return False

        if self.PointerCount > 0x1000000 or self.PointerCount < 0:
            return False

        return True

    type_map = {
        2: 'Type',
        3: 'Directory',
        4: 'SymbolicLink',
        5: 'Token',
        6: 'Job',
        7: 'Process',
        8: 'Thread',
        9: 'UserApcReserve',
        10: 'IoCompletionReserve',
        11: 'Silo',
        12: 'DebugObject',
        13: 'Event',
        14: 'Mutant',
        15: 'Callback',
        16: 'Semaphore',
        17: 'Timer',
        18: 'IRTimer',
        19: 'Profile',
        20: 'KeyedEvent',
        21: 'WindowStation',
        22: 'Desktop',
        23: 'Composition',
        24: 'RawInputManager',
        25: 'TpWorkerFactory',
        26: 'Adapter',
        27: 'Controller',
        28: 'Device',
        29: 'Driver',
        30: 'IoCompletion',
        31: 'WaitCompletionPacket',
        32: 'File',
        33: 'TmTm',
        34: 'TmTx',
        35: 'TmRm',
        36: 'TmEn',
        37: 'Section',
        38: 'Session',
        39: 'Partition',
        40: 'Key',
        41: 'ALPC Port',
        42: 'PowerRequest',
        43: 'WmiGuid',
        44: 'EtwRegistration',
        45: 'EtwConsumer',
        46: 'DmaAdapter',
        47: 'DmaDomain',
        48: 'PcwObject',
        49: 'FilterConnectionPort',
        50: 'FilterCommunicationPort',
        51: 'NetworkNamespace',
        52: 'DxgkSharedResource',
        53: 'DxgkSharedSyncObject',
        54: 'DxgkSharedSwapChainObject',
        }

class _OBJECT_HEADER_10_1AC738FB(_OBJECT_HEADER_10):

    type_map = {
        2: 'Type',
        3: 'Directory',
        4: 'SymbolicLink',
        5: 'Token',
        6: 'Job',
        7: 'Process',
        8: 'Thread',
        9: 'UserApcReserve',
        10: 'IoCompletionReserve',
        11: 'DebugObject',
        12: 'Event',
        13: 'Mutant',
        14: 'Callback',
        15: 'Semaphore',
        16: 'Timer',
        17: 'IRTimer',
        18: 'Profile',
        19: 'KeyedEvent',
        20: 'WindowStation',
        21: 'Desktop',
        22: 'Composition',
        23: 'RawInputManager',
        24: 'TpWorkerFactory',
        25: 'Adapter',
        26: 'Controller',
        27: 'Device',
        28: 'Driver',
        29: 'IoCompletion',
        30: 'WaitCompletionPacket',
        31: 'File',
        32: 'TmTm',
        33: 'TmTx',
        34: 'TmRm',
        35: 'TmEn',
        36: 'Section',
        37: 'Session',
        38: 'Partition',
        39: 'Key',
        40: 'ALPC Port',
        41: 'PowerRequest',
        42: 'WmiGuid',
        43: 'EtwRegistration',
        44: 'EtwConsumer',
        45: 'DmaAdapter',
        46: 'DmaDomain',
        47: 'PcwObject',
        48: 'FilterConnectionPort',
        49: 'FilterCommunicationPort',
        50: 'NetworkNamespace',
        51: 'DxgkSharedResource',
        52: 'DxgkSharedSyncObject',
        53: 'DxgkSharedSwapChainObject',
        }

class _OBJECT_HEADER_10_DD08DD42(_OBJECT_HEADER_10):

    type_map = {
        2: 'Type',
        3: 'Directory',
        4: 'SymbolicLink',
        5: 'Token',
        6: 'Job',
        7: 'Process',
        8: 'Thread',
        9: 'UserApcReserve',
        10: 'IoCompletionReserve',
        11: 'PsSiloContextPaged',
        12: 'PsSiloContextNonPaged',
        13: 'DebugObject',
        14: 'Event',
        15: 'Mutant',
        16: 'Callback',
        17: 'Semaphore',
        18: 'Timer',
        19: 'IRTimer',
        20: 'Profile',
        21: 'KeyedEvent',
        22: 'WindowStation',
        23: 'Desktop',
        24: 'Composition',
        25: 'RawInputManager',
        26: 'CoreMessaging',
        27: 'TpWorkerFactory',
        28: 'Adapter',
        29: 'Controller',
        30: 'Device',
        31: 'Driver',
        32: 'IoCompletion',
        33: 'WaitCompletionPacket',
        34: 'File',
        35: 'TmTm',
        36: 'TmTx',
        37: 'TmRm',
        38: 'TmEn',
        39: 'Section',
        40: 'Session',
        41: 'Partition',
        42: 'Key',
        43: 'RegistryTransaction',
        44: 'ALPC',
        45: 'PowerRequest',
        46: 'WmiGuid',
        47: 'EtwRegistration',
        48: 'EtwConsumer',
        49: 'DmaAdapter',
        50: 'DmaDomain',
        51: 'PcwObject',
        52: 'FilterConnectionPort',
        53: 'FilterCommunicationPort',
        54: 'NdisCmState',
        55: 'DxgkSharedResource',
        56: 'DxgkSharedSyncObject',
        57: 'DxgkSharedSwapChainObject',
        58: 'VRegConfigurationContext',
        59: 'VirtualKey',
        }
    
class _OBJECT_HEADER_10_15063(_OBJECT_HEADER_10):

    type_map = {
		2: 'Type',
		3: 'Directory',
		4: 'SymbolicLink',
		5: 'Token',
		6: 'Job',
		7: 'Process',
		8: 'Thread',
		9: 'UserApcReserve',
		10: 'IoCompletionReserve',
		11: 'ActivityReference',
		12: 'PsSiloContextPaged',
		13: 'PsSiloContextNonPaged',
		14: 'DebugObject',
		15: 'Event',
		16: 'Mutant',
		17: 'Callback',
		18: 'Semaphore',
		19: 'Timer',
		20: 'IRTimer',
		21: 'Profile',
		22: 'KeyedEvent',
		23: 'WindowStation',
		24: 'Desktop',
		25: 'Composition',
		26: 'RawInputManager',
		27: 'CoreMessaging',
		28: 'TpWorkerFactory',
		29: 'Adapter',
		30: 'Controller',
		31: 'Device',
		32: 'Driver',
		33: 'IoCompletion',
		34: 'WaitCompletionPacket',
		35: 'File',
		36: 'TmTm',
		37: 'TmTx',
		38: 'TmRm',
		39: 'TmEn',
		40: 'Section',
		41: 'Session',
		42: 'Partition',
		43: 'Key',
		44: 'RegistryTransaction',
		45: 'ALPC Port',
		46: 'PowerRequest',
		47: 'WmiGuid',
		48: 'EtwRegistration',
		49: 'EtwSessionDemuxEntry',
		50: 'EtwConsumer',
		51: 'DmaAdapter',
		52: 'DmaDomain',
		53: 'PcwObject',
		54: 'FilterConnectionPort',
		55: 'FilterCommunicationPort',
		56: 'NdisCmState',
		57: 'DxgkSharedResource',
		58: 'DxgkSharedSyncObject',
		59: 'DxgkSharedSwapChainObject',
        60: 'DxgkCurrentDxgProcessObject',
        61: 'VRegConfigurationContext'
    	}
    
class _OBJECT_HEADER_10_16299(_OBJECT_HEADER_10):

    type_map = {
		2: 'Type',
        3: 'Directory',
        4: 'SymbolicLink',
        5: 'Token',
        6: 'Job',
        7: 'Process',
        8: 'Thread',
        9: 'Partition',
        10: 'UserApcReserve',
        11: 'IoCompletionReserve',
        12: 'ActivityReference',
        13: 'PsSiloContextPaged',
        14: 'PsSiloContextNonPaged',
        15: 'DebugObject',
        16: 'Event',
        17: 'Mutant',
        18: 'Callback',
        19: 'Semaphore',
        20: 'Timer',
        21: 'IRTimer',
        22: 'Profile',
        23: 'KeyedEvent',
        24: 'WindowStation',
        25: 'Desktop',
        26: 'Composition',
        27: 'RawInputManager',
        28: 'CoreMessaging',
        29: 'TpWorkerFactory',
        30: 'Adapter',
        31: 'Controller',
        32: 'Device',
        33: 'Driver',
        34: 'IoCompletion',
        35: 'WaitCompletionPacket',
        36: 'File',
        37: 'TmTm',
        38: 'TmTx',
        39: 'TmRm',
        40: 'TmEn',
        41: 'Section',
        42: 'Session',
        43: 'Key',
        44: 'RegistryTransaction',
        45: 'ALPC Port',
        46: 'EnergyTracker',
        47: 'PowerRequest',
        48: 'WmiGuid',
        49: 'EtwRegistration',
        50: 'EtwSessionDemuxEntry',
        51: 'EtwConsumer',
        52: 'DmaAdapter',
        53: 'DmaDomain',
        54: 'PcwObject',
        55: 'FilterConnectionPort',
        56: 'FilterCommunicationPort',
        57: 'NdisCmState',
        58: 'DxgkSharedResource',
        59: 'DxgkSharedSyncObject',
        60: 'DxgkSharedSwapChainObject',
        61: 'DxgkDisplayManagerObject',
        62: 'DxgkCurrentDxgProcessObject',
        63: 'DxgkSharedProtectedSessionObject',
        64: 'DxgkSharedBundleObject',
        65: 'VRegConfigurationContext',
    	}

class _OBJECT_HEADER_10_17134(_OBJECT_HEADER_10):

    type_map = {
        2: "Type",
        3: "Directory",
        4: "SymbolicLink",
        5: "Token",
        6: "Job",
        7: "Process",
        8: "Thread",
        9: "Partition",
        10: "UserApcReserve",
        11: "IoCompletionReserve",
        12: "ActivityReference",
        13: "PsSiloContextPaged",
        14: "PsSiloContextNonPaged",
        15: "DebugObject",
        16: "Event",
        17: "Mutant",
        18: "Callback",
        19: "Semaphore",
        20: "Timer",
        21: "IRTimer",
        22: "Profile",
        23: "KeyedEvent",
        24: "WindowStation",
        25: "Desktop",
        26: "Composition",
        27: "RawInputManager",
        28: "CoreMessaging",
        29: "TpWorkerFactory",
        30: "Adapter",
        31: "Controller",
        32: "Device",
        33: "Driver",
        34: "IoCompletion",
        35: "WaitCompletionPacket",
        36: "File",
        37: "TmTm",
        38: "TmTx",
        39: "TmRm",
        40: "TmEn",
        41: "Section",
        42: "Session",
        43: "Key",
        44: "RegistryTransaction",
        45: "ALPC",
        46: "EnergyTracker",
        47: "PowerRequest",
        48: "WmiGuid",
        49: "EtwRegistration",
        50: "EtwSessionDemuxEntry",
        51: "EtwConsumer",
        52: "CoverageSampler",
        53: "DmaAdapter",
        54: "PcwObject",
        55: "FilterConnectionPort",
        56: "FilterCommunicationPort",
        57: "NdisCmState",
        58: "DxgkSharedResource",
        59: "DxgkSharedKeyedMutexObject",
        60: "DxgkSharedSyncObject",
        61: "DxgkSharedSwapChainObject",
        62: "DxgkDisplayManagerObject",
        63: "DxgkCurrentDxgProcessObject",
        64: "DxgkSharedProtectedSessionObject",
        65: "DxgkSharedBundleObject",
        66: "DxgkCompositionObject",
        67: "VRegConfigurationContext",
    }

class _HANDLE_TABLE_10_DD08DD42(win8._HANDLE_TABLE_81R264):
    
    def decode_pointer(self, value):
        
        value = value & 0xFFFFFFFFFFFFFFF8
        value = value >> self.DECODE_MAGIC
        if (value & (1 << 47)):
            value = value | 0xFFFF000000000000
    
        return value

class Win10ObjectHeader(obj.ProfileModification):
    before = ["Win8ObjectClasses"]
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4}

    def modification(self, profile):

        metadata = profile.metadata
        build = metadata.get("build", 0)

        if build >= 17134:
            header = _OBJECT_HEADER_10_17134

            ## update the handle table here as well
            if metadata.get("memory_model") == "64bit":
                profile.object_classes.update({
                    "_HANDLE_TABLE": _HANDLE_TABLE_10_DD08DD42})

        elif build >= 16299:
            header = _OBJECT_HEADER_10_16299

            ## update the handle table here as well
            if metadata.get("memory_model") == "64bit":
                profile.object_classes.update({
                    "_HANDLE_TABLE": _HANDLE_TABLE_10_DD08DD42})

        elif build >= 15063:
            header = _OBJECT_HEADER_10_15063

            ## update the handle table here as well
            if metadata.get("memory_model") == "64bit":
                profile.object_classes.update({
                    "_HANDLE_TABLE": _HANDLE_TABLE_10_DD08DD42})

        elif build >= 14393:
            header = _OBJECT_HEADER_10_DD08DD42
            
            ## update the handle table here as well
            if metadata.get("memory_model") == "64bit":
                profile.object_classes.update({
                    "_HANDLE_TABLE": _HANDLE_TABLE_10_DD08DD42})
            
        elif build >= 10586:
            header = _OBJECT_HEADER_10_1AC738FB
        else:
            header = _OBJECT_HEADER_10

        profile.object_classes.update({"_OBJECT_HEADER": header})

class WSLPicoModifcation(obj.ProfileModification): 
    """Profile modification for Windows Subsystem for Linux, 
    in particular the Pico process contexts"""

    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4, 
                  'memory_model': lambda x: x == '64bit'}
                  
    def modification(self, profile):
        
        build = profile.metadata.get("build", 0)
        
        if build <= 14393:
            # offsets for anniversary update
            pico_context = {'_PICO_CONTEXT' : [ None, {
                "Name": [ 0x178, ["_UNICODE_STRING"]]}]}
        else:
            # offsets for creators & fall creators  
            pico_context = {'_PICO_CONTEXT' : [ None, {
                "Name": [ 0x180, ["_UNICODE_STRING"]]}]}
        
        profile.vtypes.update(pico_context)
        
        profile.merge_overlay({'_EPROCESS': [ None, {
            'PicoContext' : [ None, ['pointer', ['_PICO_CONTEXT']]],
            }]})

class Win10PoolHeader(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  'build': lambda x: x == 10586}

    def modification(self, profile):

        meta = profile.metadata
        memory_model = meta.get("memory_model", "32bit")

        if memory_model == "32bit":
            pool_types = {'_POOL_HEADER' : [ 0x8, {
                'PreviousSize' : [ 0x0, ['BitField', dict(start_bit = 0, end_bit = 9, native_type='unsigned short')]],
                'PoolIndex' : [ 0x0, ['BitField', dict(start_bit = 9, end_bit = 16, native_type='unsigned short')]],
                'BlockSize' : [ 0x2, ['BitField', dict(start_bit = 0, end_bit = 9, native_type='unsigned short')]],
                'PoolType' : [ 0x2, ['BitField', dict(start_bit = 9, end_bit = 16, native_type='unsigned short')]],
                'Ulong1' : [ 0x0, ['unsigned long']],
                'PoolTag' : [ 0x4, ['unsigned long']],
                'AllocatorBackTraceIndex' : [ 0x4, ['unsigned short']],
                'PoolTagHash' : [ 0x6, ['unsigned short']],
                }]}
        else:
            pool_types = {'_POOL_HEADER' : [ 0x10, {
                 'PreviousSize' : [ 0x0, ['BitField', dict(start_bit = 0, end_bit = 8, native_type='unsigned short')]],
                 'PoolIndex' : [ 0x0, ['BitField', dict(start_bit = 8, end_bit = 16, native_type='unsigned short')]],
                 'BlockSize' : [ 0x2, ['BitField', dict(start_bit = 0, end_bit = 8, native_type='unsigned short')]],
                 'PoolType' : [ 0x2, ['BitField', dict(start_bit = 8, end_bit = 16, native_type='unsigned short')]],
                 'Ulong1' : [ 0x0, ['unsigned long']],
                 'PoolTag' : [ 0x4, ['unsigned long']],
                 'ProcessBilled' : [ 0x8, ['pointer64', ['_EPROCESS']]],
                 'AllocatorBackTraceIndex' : [ 0x8, ['unsigned short']],
                 'PoolTagHash' : [ 0xa, ['unsigned short']],
                 }]}

        profile.vtypes.update(pool_types)

class Win10x64(obj.Profile):
    """ A Profile for Windows 10 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 9841
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x64_10240_17770(obj.Profile):
    """ A Profile for Windows 10 x64 (10.0.10240.17770 / 2018-02-10) """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 10240
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_10240_17770_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x64_10586(obj.Profile):
    """ A Profile for Windows 10 x64 (10.0.10586.306 / 2016-04-23) """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 10586
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_1AC738FB_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x64_14393(obj.Profile):
    """ A Profile for Windows 10 x64 (10.0.14393.0 / 2016-07-16) """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 14393
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_DD08DD42_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x86(obj.Profile):
    """ A Profile for Windows 10 x86 """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 9841
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x86_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x86_10240_17770(obj.Profile):
    """ A Profile for Windows 10 x86 (10.0.10240.17770 / 2018-02-10) """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 10240
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x86_10240_17770_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x86_10586(obj.Profile):
    """ A Profile for Windows 10 x86 (10.0.10586.420 / 2016-05-28) """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 10586
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x86_44B89EEA_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x86_14393(obj.Profile):
    """ A Profile for Windows 10 x86 (10.0.14393.0 / 2016-07-16) """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 14393
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x86_9619274A_vtypes'
    _md_product = ["NtProductWinNt"]
    
class Win2016x64_14393(Win10x64_14393):
    """ A Profile for Windows Server 2016 x64 (10.0.14393.0 / 2016-07-16) """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 14393
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_DD08DD42_vtypes'
    _md_product = ["NtProductLanManNt", "NtProductServer"]

class Win10x86_15063(obj.Profile):
    """ A Profile for Windows 10 x86 (10.0.15063.0 / 2017-04-04) """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 15063
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x86_15063_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x86_16299(obj.Profile):
    """ A Profile for Windows 10 x86 (10.0.16299.15 / 2017-09-29) """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 16299
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x86_16299_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x86_17134(obj.Profile):
    """ A Profile for Windows 10 x86 (10.0.17134.1 / 2018-04-11) """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 17134
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x86_17134_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x64_15063(obj.Profile):
    """ A Profile for Windows 10 x64 (10.0.15063.0 / 2017-04-04) """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 15063
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_15063_vtypes'
    _md_product = ["NtProductWinNt"]
    
class Win10x64_16299(obj.Profile):
    """ A Profile for Windows 10 x64 (10.0.16299.0 / 2017-09-22) """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 16299
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_16299_vtypes'
    _md_product = ["NtProductWinNt"]

class Win10x64_17134(obj.Profile):
    """ A Profile for Windows 10 x64 (10.0.17134.1 / 2018-04-11) """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 17134
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_17134_vtypes'
    _md_product = ["NtProductWinNt"]