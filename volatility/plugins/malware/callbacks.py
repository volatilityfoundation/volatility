# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
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

import volatility.utils as utils
import volatility.obj as obj
import volatility.poolscan as poolscan
import volatility.debug as debug
import volatility.plugins.common as common
import volatility.win32.modules as modules
import volatility.win32.tasks as tasks
import volatility.plugins.malware.devicetree as devicetree
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False

#--------------------------------------------------------------------------------
# vtypes
#--------------------------------------------------------------------------------

callback_types = {
    '_NOTIFICATION_PACKET' : [ 0x10, {
    'ListEntry' : [ 0x0, ['_LIST_ENTRY']],
    'DriverObject' : [ 0x8, ['pointer', ['_DRIVER_OBJECT']]],
    'NotificationRoutine' : [ 0xC, ['unsigned int']],
    } ],
    '_KBUGCHECK_CALLBACK_RECORD' : [ 0x20, {
    'Entry' : [ 0x0, ['_LIST_ENTRY']],
    'CallbackRoutine' : [ 0x8, ['unsigned int']],
    'Buffer' : [ 0xC, ['pointer', ['void']]],
    'Length' : [ 0x10, ['unsigned int']],
    'Component' : [ 0x14, ['pointer', ['String', dict(length = 64)]]],
    'Checksum' : [ 0x18, ['pointer', ['unsigned int']]],
    'State' : [ 0x1C, ['unsigned char']],
    } ],
    '_KBUGCHECK_REASON_CALLBACK_RECORD' : [ 0x1C, {
    'Entry' : [ 0x0, ['_LIST_ENTRY']],
    'CallbackRoutine' : [ 0x8, ['unsigned int']],
    'Component' : [ 0xC, ['pointer', ['String', dict(length = 8)]]],
    'Checksum' : [ 0x10, ['pointer', ['unsigned int']]],
    'Reason' : [ 0x14, ['unsigned int']],
    'State' : [ 0x18, ['unsigned char']],
    } ],
    '_SHUTDOWN_PACKET' : [ 0xC, {
    'Entry' : [ 0x0, ['_LIST_ENTRY']],
    'DeviceObject' : [ 0x8, ['pointer', ['_DEVICE_OBJECT']]],
    } ],
    '_EX_CALLBACK_ROUTINE_BLOCK' : [ 0x8, {
    'RundownProtect' : [ 0x0, ['unsigned int']],
    'Function' : [ 0x4, ['unsigned int']],
    'Context' : [ 0x8, ['unsigned int']],
    } ],
    '_GENERIC_CALLBACK' : [ 0xC, {
    'Callback' : [ 0x4, ['pointer', ['void']]],
    'Associated' : [ 0x8, ['pointer', ['void']]],
    } ],
    '_REGISTRY_CALLBACK_LEGACY' : [ 0x38, {
    'CreateTime' : [ 0x0, ['WinTimeStamp', dict(is_utc = True)]],
    } ],
    '_REGISTRY_CALLBACK' : [ None, {
    'ListEntry' : [ 0x0, ['_LIST_ENTRY']],
    'Function' : [ 0x1C, ['pointer', ['void']]],
    } ],
    '_DBGPRINT_CALLBACK' : [ 0x14, {
    'Function' : [ 0x8, ['pointer', ['void']]],
    } ],
    '_NOTIFY_ENTRY_HEADER' : [ None, {
    'ListEntry' : [ 0x0, ['_LIST_ENTRY']],
    'EventCategory' : [ 0x8, ['Enumeration', dict(target = 'long', choices = {
            0: 'EventCategoryReserved',
            1: 'EventCategoryHardwareProfileChange',
            2: 'EventCategoryDeviceInterfaceChange',
            3: 'EventCategoryTargetDeviceChange'})]],
    'CallbackRoutine' : [ 0x14, ['unsigned int']],
    'DriverObject' : [ 0x1C, ['pointer', ['_DRIVER_OBJECT']]],
    } ],
}

callback_types_x64 = {
    '_GENERIC_CALLBACK' : [ 0x18, {
    'Callback' : [ 0x8, ['pointer', ['void']]],
    'Associated' : [ 0x10, ['pointer', ['void']]],
    } ],
    '_NOTIFICATION_PACKET' : [ 0x30, {
    'ListEntry' : [ 0x0, ['_LIST_ENTRY']],
    'DriverObject' : [ 0x10, ['pointer', ['_DRIVER_OBJECT']]],
    'NotificationRoutine' : [ 0x18, ['address']],
    } ],
    '_SHUTDOWN_PACKET' : [ 0xC, {
    'Entry' : [ 0x0, ['_LIST_ENTRY']],
    'DeviceObject' : [ 0x10, ['pointer', ['_DEVICE_OBJECT']]],
    } ],
    '_DBGPRINT_CALLBACK' : [ 0x14, {
    'Function' : [ 0x10, ['pointer', ['void']]], 
    } ],
    '_NOTIFY_ENTRY_HEADER' : [ None, {
    'ListEntry' : [ 0x0, ['_LIST_ENTRY']],
    'EventCategory' : [ 0x10, ['Enumeration', dict(target = 'long', choices = {
            0: 'EventCategoryReserved',
            1: 'EventCategoryHardwareProfileChange',
            2: 'EventCategoryDeviceInterfaceChange',
            3: 'EventCategoryTargetDeviceChange'})]],
    'CallbackRoutine' : [ 0x20, ['address']],
    'DriverObject' : [ 0x30, ['pointer', ['_DRIVER_OBJECT']]],
    } ],
    '_REGISTRY_CALLBACK' : [ 0x50, {
    'ListEntry' : [ 0x0, ['_LIST_ENTRY']],
    'Function' : [ 0x20, ['pointer', ['void']]], # other could be 28
    } ],
    '_KBUGCHECK_CALLBACK_RECORD' : [ None, {
    'Entry' : [ 0x0, ['_LIST_ENTRY']],
    'CallbackRoutine' : [ 0x10, ['address']],
    'Component' : [ 0x28, ['pointer', ['String', dict(length = 8)]]],
    } ],
    '_KBUGCHECK_REASON_CALLBACK_RECORD' : [ None, {
    'Entry' : [ 0x0, ['_LIST_ENTRY']],
    'CallbackRoutine' : [ 0x10, ['unsigned int']],
    'Component' : [ 0x28, ['pointer', ['String', dict(length = 8)]]],
    } ],
}

#--------------------------------------------------------------------------------
# object classes
#--------------------------------------------------------------------------------

class _SHUTDOWN_PACKET(obj.CType):
    """Class for shutdown notification callbacks"""

    def is_valid(self):
        """
        Perform some checks. 
        Note: obj_native_vm is kernel space.
        """

        if not obj.CType.is_valid(self):
            return False

        if (not self.obj_native_vm.is_valid_address(self.Entry.Flink) or
            not self.obj_native_vm.is_valid_address(self.Entry.Blink) or
            not self.obj_native_vm.is_valid_address(self.DeviceObject)):
            return False

        # Dereference the device object 
        device = self.DeviceObject.dereference()

        # Carve out the device's object header and check its type
        object_header = obj.Object("_OBJECT_HEADER",
                offset = device.obj_offset -
                self.obj_native_vm.profile.get_obj_offset("_OBJECT_HEADER", "Body"),
                vm = device.obj_vm,
                native_vm = device.obj_native_vm)

        return object_header.get_object_type() == "Device"

#--------------------------------------------------------------------------------
# profile modifications 
#--------------------------------------------------------------------------------

class CallbackMods(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        if profile.metadata.get("memory_model", "32bit") == "32bit":
            profile.vtypes.update(callback_types)
            profile.object_classes.update({
                '_SHUTDOWN_PACKET': _SHUTDOWN_PACKET,
            })
        else:
            profile.vtypes.update(callback_types_x64)

#--------------------------------------------------------------------------------
# pool scanners
#--------------------------------------------------------------------------------

class AbstractCallbackScanner(poolscan.PoolScanner):
    """Return the offset of the callback, no object headers"""

class PoolScanFSCallback(AbstractCallbackScanner):
    """PoolScanner for File System Callbacks"""

    def __init__(self, address_space):
        AbstractCallbackScanner.__init__(self, address_space)

        self.pooltag = "IoFs"
        self.struct_name = "_NOTIFICATION_PACKET"

        if address_space.profile.metadata.get("memory_model", "32bit") == "32bit":
            size = 0x18
        else:
            size = 0x30

        self.checks = [ ('CheckPoolSize', dict(condition = lambda x: x == size)),
                   ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
                   #('CheckPoolIndex', dict(value = 4)),
                   ]

class PoolScanShutdownCallback(AbstractCallbackScanner):
    """PoolScanner for Shutdown Callbacks"""

    def __init__(self, address_space):
        AbstractCallbackScanner.__init__(self, address_space)

        self.pooltag = "IoSh"
        self.struct_name = "_SHUTDOWN_PACKET"

        if address_space.profile.metadata.get("memory_model", "32bit") == "32bit":
            size = 0x18
        else:
            size = 0x30

        self.checks = [ ('CheckPoolSize', dict(condition = lambda x: x == size)),
                   ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
                   ('CheckPoolIndex', dict(value = 0)),
                   ]

class PoolScanGenericCallback(AbstractCallbackScanner):
    """PoolScanner for Generic Callbacks"""

    def __init__(self, address_space):
        AbstractCallbackScanner.__init__(self, address_space)

        self.pooltag = "Cbrb"
        self.struct_name = "_GENERIC_CALLBACK"

        if address_space.profile.metadata.get("memory_model", "32bit") == "32bit":
            size = 0x18
        else:
            size = 0x30

        self.checks = [ ('CheckPoolSize', dict(condition = lambda x: x == size)),
                   ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
                   # This is a good constraint for all images except Frank's rustock-c.vmem
                   #('CheckPoolIndex', dict(value = 1)), 
                   ]

class PoolScanDbgPrintCallback(AbstractCallbackScanner):
    """PoolScanner for DebugPrint Callbacks on Vista and 7"""

    def __init__(self, address_space):
        AbstractCallbackScanner.__init__(self, address_space)

        self.pooltag = "DbCb"
        self.struct_name = "_DBGPRINT_CALLBACK"

        self.checks = [ ('CheckPoolSize', dict(condition = lambda x: x >= 0x20 and x <= 0x40)),
                   ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
                   #('CheckPoolIndex', dict(value = 0)), 
                   ]

class PoolScanRegistryCallback(AbstractCallbackScanner):
    """PoolScanner for DebugPrint Callbacks on Vista and 7"""

    def __init__(self, address_space):
        AbstractCallbackScanner.__init__(self, address_space)

        self.pooltag = "CMcb"
        self.struct_name = "_REGISTRY_CALLBACK"

        self.checks = [('CheckPoolSize', dict(condition = lambda x: x >= 0x38)),
                   ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
                   ('CheckPoolIndex', dict(value = 4)),
                   ]

class PoolScanPnp9(AbstractCallbackScanner):
    """PoolScanner for Pnp9 (EventCategoryHardwareProfileChange)"""

    def __init__(self, address_space):
        AbstractCallbackScanner.__init__(self, address_space)

        self.pooltag = "Pnp9"
        self.struct_name = "_NOTIFY_ENTRY_HEADER"

        self.checks = [ # seen as 0x2C on W7, 0x28 on vistasp0 (4 less but needs 8 less)
                   ('CheckPoolSize', dict(condition = lambda x: x >= 0x30)),
                   ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
                   ('CheckPoolIndex', dict(value = 1)),
                   ]

class PoolScanPnpD(AbstractCallbackScanner):
    """PoolScanner for PnpD (EventCategoryDeviceInterfaceChange)"""

    def __init__(self, address_space):
        AbstractCallbackScanner.__init__(self, address_space)

        self.pooltag = "PnpD"
        self.struct_name = "_NOTIFY_ENTRY_HEADER"

        self.checks = [('CheckPoolSize', dict(condition = lambda x: x >= 0x40)),
                   ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
                   ('CheckPoolIndex', dict(value = 1)),
                   ]

class PoolScanPnpC(AbstractCallbackScanner):
    """PoolScanner for PnpC (EventCategoryTargetDeviceChange)"""

    def __init__(self, address_space):
        AbstractCallbackScanner.__init__(self, address_space)

        self.pooltag = "PnpC"
        self.struct_name = "_NOTIFY_ENTRY_HEADER"

        self.checks = [('CheckPoolSize', dict(condition = lambda x: x >= 0x38)),
                   ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
                   ('CheckPoolIndex', dict(value = 1)),
                   ]

#--------------------------------------------------------------------------------
# callbacks plugin
#--------------------------------------------------------------------------------

class Callbacks(common.AbstractScanCommand):
    """Print system-wide notification routines"""

    scanners = [PoolScanFSCallback, PoolScanShutdownCallback, PoolScanGenericCallback]
    
    @staticmethod
    def get_kernel_callbacks(nt_mod):
        """
        Enumerate the Create Process, Create Thread, and Image Load callbacks.

        On some systems, the byte sequences will be inaccurate or the exported 
        function will not be found. In these cases, the PoolScanGenericCallback
        scanner will pick up the pool associated with the callbacks.
        """

        bits32 = nt_mod.obj_vm.profile.metadata.get("memory_model", "32bit") == "32bit"
        vista_or_later = nt_mod.obj_vm.profile.metadata.get("major", 0) >= 6

        if bits32:
            routines = [
                   # push esi; mov esi, offset _PspLoadImageNotifyRoutine
                   ('PsSetLoadImageNotifyRoutine', "\x56\xbe"),
                   # push esi; mov esi, offset _PspCreateThreadNotifyRoutine
                   ('PsSetCreateThreadNotifyRoutine', "\x56\xbe"),
                   # mov edi, offset _PspCreateProcessNotifyRoutine
                   ('PsSetCreateProcessNotifyRoutine', "\xbf"),
                   ]
        else:
            routines = [
                   # lea ecx, offset _PspLoadImageNotifyRoutine
                   ('PsRemoveLoadImageNotifyRoutine', "\x48\x8d\x0d"),
                   # lea rcx, offset _PspCreateThreadNotifyRoutine
                   ('PsRemoveCreateThreadNotifyRoutine', "\x48\x8d\x0d"),
                   # mov edi, offset _PspCreateProcessNotifyRoutine
                   #('PsSetCreateProcessNotifyRoutine', "\xbf"),
                   ]

        for symbol, hexbytes in routines:

            # Locate the exported symbol in the NT module
            symbol_rva = nt_mod.getprocaddress(symbol)
            if symbol_rva == None:
                continue

            symbol_address = symbol_rva + nt_mod.DllBase

            # Find the global variable referenced by the exported symbol
            data = nt_mod.obj_vm.zread(symbol_address, 100)

            offset = data.find(hexbytes)
            if offset == -1:
                continue

            if bits32:
                # Read the pointer to the list 
                p = obj.Object('Pointer',
                        offset = symbol_address + offset + len(hexbytes),
                        vm = nt_mod.obj_vm)
            else:
                # Read the pointer to the list 
                v = obj.Object('int',
                        offset = symbol_address + offset + len(hexbytes),
                        vm = nt_mod.obj_vm)
                p = symbol_address + offset + 7 + v

            # The list is an array of 8 _EX_FAST_REF objects on XP/2003 
            # and 64 starting with NT6 (Visa) and later

            if vista_or_later and ('CreateProcess' in symbol or 'CreateThread' in symbol):
                count = 64
            else:
                count = 8

            addrs = obj.Object('Array', count = 8, targetType = '_EX_FAST_REF',
                    offset = p, vm = nt_mod.obj_vm)

            for addr in addrs:
                callback = addr.dereference_as("_GENERIC_CALLBACK")
                if callback:
                    yield symbol, callback.Callback, None

    @staticmethod
    def get_bugcheck_callbacks(addr_space):
        """
        Enumerate generic Bugcheck callbacks.

        Note: These structures don't exist in tagged pools, but you can find 
        them via KDDEBUGGER_DATA64 on all versions of Windows.
        """

        kdbg = tasks.get_kdbg(addr_space)
        list_head = kdbg.KeBugCheckCallbackListHead.dereference_as('_KBUGCHECK_CALLBACK_RECORD')

        for l in list_head.Entry.list_of_type("_KBUGCHECK_CALLBACK_RECORD", "Entry"):
            yield "KeBugCheckCallbackListHead", l.CallbackRoutine, l.Component.dereference()

    @staticmethod
    def get_registry_callbacks_legacy(nt_mod):
        """
        Enumerate registry change callbacks.

        This method of finding a global variable via disassembly of the 
        CmRegisterCallback function is only for XP systems. If it fails on 
        XP you can still find the callbacks using PoolScanGenericCallback. 

        On Vista and Windows 7, these callbacks are registered using the 
        CmRegisterCallbackEx function. 
        """

        if not has_distorm3:
            return

        symbol = "CmRegisterCallback"

        # Get the RVA of the symbol from NT's EAT
        symbol_rva = nt_mod.getprocaddress(symbol)
        if symbol_rva == None:
            return

        # Absolute VA to the symbol code 
        symbol_address = symbol_rva + nt_mod.DllBase

        # Read the function prologue 
        data = nt_mod.obj_vm.zread(symbol_address, 200)

        c = 0
        vector = None

        # Looking for MOV EBX, CmpCallBackVector
        # This may be the first or second MOV EBX instruction
        for op in distorm3.Decompose(symbol_address, data, distorm3.Decode32Bits):
            if (op.valid and op.mnemonic == "MOV" 
                        and len(op.operands) == 2 
                        and op.operands[0].name == 'EBX'):
                vector = op.operands[1].value
                if c == 1:
                    break
                else:
                    c += 1

        # Can't find the global variable 
        if vector == None:
            return

        # The vector is an array of 100 _EX_FAST_REF objects
        addrs = obj.Object("Array", count = 100, offset = vector,
                    vm = nt_mod.obj_vm, targetType = "_EX_FAST_REF")

        for addr in addrs:
            callback = addr.dereference_as("_EX_CALLBACK_ROUTINE_BLOCK")
            if callback:
                yield symbol, callback.Function, None

    @staticmethod
    def get_bugcheck_reason_callbacks(nt_mod):
        """
        Enumerate Bugcheck Reason callbacks.

        Note: These structures don't exist in tagged pools, so we 
        find them by locating the list head which is a non-exported 
        NT symbol. The method works on all x86 versions of Windows. 

        mov [eax+KBUGCHECK_REASON_CALLBACK_RECORD.Entry.Blink], \
                offset _KeBugCheckReasonCallbackListHead
        """

        symbol = "KeRegisterBugCheckReasonCallback"

        bits32 = nt_mod.obj_vm.profile.metadata.get("memory_model", "32bit") == "32bit"

        if bits32:
            hexbytes = "\xC7\x40\x04"
        else:
            hexbytes = "\x48\x8d\x0d"

        # Locate the symbol RVA 
        symbol_rva = nt_mod.getprocaddress(symbol)
        if symbol_rva == None:
            return

        # Compute the absolute virtual address 
        symbol_address = symbol_rva + nt_mod.DllBase

        data = nt_mod.obj_vm.zread(symbol_address, 200)

        # Search for the pattern 
        offset = data.find(hexbytes)
        if offset == -1:
            return

        if bits32:
            p = obj.Object('Pointer',
                    offset = symbol_address + offset + len(hexbytes),
                    vm = nt_mod.obj_vm)
            bugs = p.dereference_as('_KBUGCHECK_REASON_CALLBACK_RECORD')
        else:
            v = obj.Object("int", offset = symbol_address + offset + len(hexbytes), vm = nt_mod.obj_vm)
            p = symbol_address + offset + 7 + v
            bugs = obj.Object("_KBUGCHECK_REASON_CALLBACK_RECORD", offset = p, vm = nt_mod.obj_vm)

        for l in bugs.Entry.list_of_type("_KBUGCHECK_REASON_CALLBACK_RECORD", "Entry"):
            if nt_mod.obj_vm.is_valid_address(l.CallbackRoutine):
                yield symbol, l.CallbackRoutine, l.Component.dereference()

    def calculate(self):
        addr_space = utils.load_as(self._config)

        bits32 = addr_space.profile.metadata.get("memory_model", "32bit") == "32bit"

        # Get the OS version we're analyzing
        version = (addr_space.profile.metadata.get('major', 0),
                   addr_space.profile.metadata.get('minor', 0))

        modlist = list(modules.lsmod(addr_space))
        mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in modlist)
        mod_addrs = sorted(mods.keys())

        # Valid for Vista and later
        if version >= (6, 0):
            self.scanners.append(PoolScanDbgPrintCallback)
            self.scanners.append(PoolScanRegistryCallback)
            self.scanners.append(PoolScanPnp9)
            self.scanners.append(PoolScanPnpD)
            self.scanners.append(PoolScanPnpC)
        
        for objct in self.scan_results(addr_space):
            name = objct.obj_name
            if name == "_REGISTRY_CALLBACK":
                info = "CmRegisterCallback", objct.Function, None
                yield info, mods, mod_addrs
            elif name == "_DBGPRINT_CALLBACK":
                info = "DbgSetDebugPrintCallback", objct.Function, None
                yield info, mods, mod_addrs
            elif name == "_SHUTDOWN_PACKET":
                driver = objct.DeviceObject.dereference().DriverObject
                if not driver:
                    continue
                index = devicetree.MAJOR_FUNCTIONS.index('IRP_MJ_SHUTDOWN')
                address = driver.MajorFunction[index]
                details = str(driver.DriverName or "-")
                info = "IoRegisterShutdownNotification", address, details
                yield info, mods, mod_addrs
            elif name == "_GENERIC_CALLBACK":
                info = "GenericKernelCallback", objct.Callback, None
                yield info, mods, mod_addrs
            elif name == "_NOTIFY_ENTRY_HEADER":
                # Dereference the driver object pointer
                driver = objct.DriverObject.dereference()
                driver_name = ""
                if driver:
                    # Instantiate an object header for the driver name 
                    header = driver.get_object_header()
                    if header.get_object_type() == "Driver":
                        # Grab the object name 
                        driver_name = header.NameInfo.Name.v()
                info = objct.EventCategory, objct.CallbackRoutine, driver_name
                yield info, mods, mod_addrs
            elif name == "_NOTIFICATION_PACKET":
                info = "IoRegisterFsRegistrationChange", objct.NotificationRoutine, None
                yield info, mods, mod_addrs
            
        for info in self.get_kernel_callbacks(modlist[0]):
            yield info, mods, mod_addrs

        for info in self.get_bugcheck_callbacks(addr_space):
            yield info, mods, mod_addrs

        for info in self.get_bugcheck_reason_callbacks(modlist[0]):
            yield info, mods, mod_addrs

        # Valid for XP 
        if bits32 and version == (5, 1):
            for info in self.get_registry_callbacks_legacy(modlist[0]):
                yield info, mods, mod_addrs

    def unified_output(self, data):
        return TreeGrid([("Type", str),
                       ("Callback", Address),
                       ("Module", str),
                       ("Details", str)],
                        self.generator(data))

    def generator(self, data):
        for (sym, cb, detail), mods, mod_addrs in data:

            module = tasks.find_module(mods, mod_addrs, mods.values()[0].obj_vm.address_mask(cb))

            ## The original callbacks plugin searched driver objects
            ## if the owning module isn't found (Rustock.B). We leave that 
            ## task up to the user this time, and will be incoporating 
            ## some different module association methods later. 
            if module:
                module_name = module.BaseDllName or module.FullDllName
            else:
                module_name = "UNKNOWN"

            yield (0, [str(sym), Address(cb), str(module_name), str(detail or "-")])

    def render_text(self, outfd, data):

        self.table_header(outfd,
                        [("Type", "36"),
                         ("Callback", "[addrpad]"),
                         ("Module", "20"),
                         ("Details", ""),
                        ])

        for (sym, cb, detail), mods, mod_addrs in data:

            module = tasks.find_module(mods, mod_addrs, mods.values()[0].obj_vm.address_mask(cb))

            ## The original callbacks plugin searched driver objects
            ## if the owning module isn't found (Rustock.B). We leave that 
            ## task up to the user this time, and will be incoporating 
            ## some different module association methods later. 
            if module:
                module_name = module.BaseDllName or module.FullDllName
            else:
                module_name = "UNKNOWN"

            self.table_row(outfd, sym, cb, module_name, detail or "-")

