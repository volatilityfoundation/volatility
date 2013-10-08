import struct
import volatility.plugins.overlays.windows.windows as windows
import volatility.obj as obj
import volatility.constants as constants
import volatility.utils as utils
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.addrspace as addrspace
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.overlays.windows.pe_vtypes as pe_vtypes
import volatility.plugins.overlays.windows.ssdt_vtypes as ssdt_vtypes
import volatility.plugins.overlays.windows.win7 as win7
import volatility.plugins.overlays.windows.vista as vista

try:
    import distorm3
    has_distorm = True
except:
    has_distorm = False

class _HANDLE_TABLE32(windows._HANDLE_TABLE):
    """A class for 32-bit Windows 8 handle tables"""    

    @property
    def HandleCount(self):
        """The Windows 8 / 2012 handle table does not have a 
        HandleCount member, so we fake it. 

        Alternately, we could return len(self.handles()) and
        show a valid number in pslist, however pslist would 
        be much slower than normal.
        """

        return 0

    def get_item(self, entry, handle_value = 0):
        """Returns the OBJECT_HEADER of the associated handle. 
        The parent is the _HANDLE_TABLE_ENTRY so that an object
        can be linked to its GrantedAccess.
        """

        if entry.InfoTable == 0:
            return obj.NoneObject("LeafHandleValue pointer is invalid")

        return obj.Object("_OBJECT_HEADER", 
                          offset = entry.InfoTable & ~7, 
                          vm = self.obj_vm, 
                          parent = entry, 
                          handle_value = handle_value)

class _HANDLE_TABLE64(_HANDLE_TABLE32):
    """A class for 64-bit Windows 8 / 2012 handle tables"""   

    def decode_pointer(self, value):
        """Decode a pointer like SAR. Since Python does not 
        have an operator for shift arithmetic, we implement
        one ourselves.
        """

        value = value & 0xFFFFFFFFFFFFFFF8
        value = value >> 0x13
        if (value & 1 << 44):
            return value | 0xFFFFF00000000000
        else:
            return value | 0xFFFF000000000000

    def get_item(self, entry, handle_value = 0):
        """Returns the OBJECT_HEADER of the associated handle. 
        The parent is the _HANDLE_TABLE_ENTRY so that an object
        can be linked to its GrantedAccess.
        """

        if entry.LowValue == 0:
            return obj.NoneObject("LowValue pointer is invalid")

        return obj.Object("_OBJECT_HEADER", 
                          offset = self.decode_pointer(entry.LowValue), 
                          vm = self.obj_vm, 
                          parent = entry, 
                          handle_value = handle_value)

class _LDR_DATA_TABLE_ENTRY(pe_vtypes._LDR_DATA_TABLE_ENTRY):
    """A class for DLL modules"""
    
    @property
    def LoadCount(self):
        """The Windows 8 / 2012 module does not have a 
        LoadCount member, so we fake it.
        """

        return 0

class _OBJECT_HEADER(win7._OBJECT_HEADER):
    """A class for object headers"""

    # This specifies the order the headers are found below the _OBJECT_HEADER
    # Note the AuditInfo field which is new as of Windows 8 / 2012
    optional_header_mask = (('CreatorInfo', '_OBJECT_HEADER_CREATOR_INFO', 0x01),
                            ('NameInfo', '_OBJECT_HEADER_NAME_INFO', 0x02),
                            ('HandleInfo', '_OBJECT_HEADER_HANDLE_INFO', 0x04),
                            ('QuotaInfo', '_OBJECT_HEADER_QUOTA_INFO', 0x08),
                            ('ProcessInfo', '_OBJECT_HEADER_PROCESS_INFO', 0x10),
                            ('AuditInfo', '_OBJECT_HEADER_AUDIT_INFO', 0x40),
                            )

    type_map = { 2: 'Type',
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
                13: 'EventPair',
                14: 'Mutant',
                15: 'Callback',
                16: 'Semaphore',
                17: 'Timer',
                18: 'IRTimer',
                19: 'Profile',
                20: 'KeyedEvent',
                21: 'WindowStation',
                22: 'Desktop',
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
                38: 'Key',
                39: 'ALPC Port',
                40: 'PowerRequest',
                41: 'WmiGuid',
                42: 'EtwRegistration',
                43: 'EtwConsumer',
                44: 'FilterConnectionPort',
                45: 'FilterCommunicationPort',
                46: 'PcwObject',
                47: 'DxgkSharedResource', 
                48: 'DxgkSharedSyncObject',
            }

    @property
    def GrantedAccess(self):
        """Return the object's granted access permissions"""

        if self.obj_parent:
            return self.obj_parent.GrantedAccessBits
        return obj.NoneObject("No parent known")


    def is_valid(self):
        """Determine if a given object header is valid"""

        if not obj.CType.is_valid(self):
            return False

        if self.InfoMask > 0x48:
            return False

        if self.PointerCount > 0x1000000 or self.PointerCount < 0:
            return False

        return True

class Win8KDBG(windows.AbstractKDBGMod):
    """The Windows 8 / 2012 KDBG signatures"""

    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 2}

    kdbgsize = 0x360

    def modification(self, profile):

        if profile.metadata.get('memory_model', '32bit') == '32bit':
            signature = '\x00\x00\x00\x00\x00\x00\x00\x00'
        else:
            signature = '\x03\xf8\xff\xff'
        signature += 'KDBG' + struct.pack('<H', self.kdbgsize)

        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'KDBGHeader': [ None, ['VolatilityMagic', dict(value = signature)]]
            }]})

class Win8x86DTB(obj.ProfileModification):
    """The Windows 8 32-bit DTB signature"""

    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 2,
                  'memory_model': lambda x: x == '32bit',
                  }

    def modification(self, profile):
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x28\x00")]],
            }]})

class Win8x64DTB(obj.ProfileModification):
    """The Windows 8 32-bit DTB signature"""

    before = ['WindowsOverlay', 'Windows64Overlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 2,
                  'memory_model': lambda x: x == '64bit',
                  }

    def modification(self, profile):
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\xb2\x00")]],
            }]})

class Win8x86SyscallVTypes(obj.ProfileModification):
    """Applying the SSDT structures for Win 8 32-bit"""

    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 2}

    def modification(self, profile):
        # Same as 2003, which basically just means there are
        # only two SSDT tables by default. 
        profile.vtypes.update(ssdt_vtypes.ssdt_vtypes_2003)

class Win8ObjectClasses(obj.ProfileModification):
    #before = ['WindowsOverlay', 'Win2003MMVad']
    before = ["WindowsObjectClasses", "Win7ObjectClasses", "WinPEObjectClasses"]
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 2}

    def modification(self, profile):

        if profile.metadata.get("memory_model", "32bit") == "32bit":
            handletable = _HANDLE_TABLE32
        else:
            handletable = _HANDLE_TABLE64

        profile.object_classes.update({
                #"_EPROCESS": _EPROCESS, 
                "_LDR_DATA_TABLE_ENTRY": _LDR_DATA_TABLE_ENTRY, 
                "_HANDLE_TABLE": handletable,
                "_OBJECT_HEADER": _OBJECT_HEADER,
                #"_POOL_HEADER": _POOL_HEADER,
                #"_MM_AVL_NODE": _MM_AVL_NODE,
                #"_MMVAD": _MM_AVL_NODE,
                })

class Win8SP0x64(obj.Profile):
    """ A Profile for Windows 8 SP0 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 2
    _md_build = 9200
    _md_vtype_module = 'volatility.plugins.overlays.windows.win8_sp0_x64_vtypes'

class Win2012SP0x64(Win8SP0x64):
    """ A Profile for Windows Server 2012 SP0 x64 """
    _md_build = 9201 ##FIXME: fake build number to indicate server 2012 vs windows 8

class Win8SP0x86(obj.Profile):
    """ A Profile for Windows 8 SP0 x86 """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 2
    _md_build = 9200
    _md_vtype_module = 'volatility.plugins.overlays.windows.win8_sp0_x86_vtypes'
