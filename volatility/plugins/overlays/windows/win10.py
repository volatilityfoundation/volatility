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
        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x2A\x00")]],
            }]})

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
        nt_mod = list(kdbg.modules())[0]

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

class Win10ObjectHeader(obj.ProfileModification):
    before = ["Win8ObjectClasses"]
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4}

    def modification(self, profile):
        profile.object_classes.update({"_OBJECT_HEADER": _OBJECT_HEADER_10})

class Win10x64(obj.Profile):
    """ A Profile for Windows 10 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 9841
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x64_vtypes'

class Win10x86(obj.Profile):
    """ A Profile for Windows 10 x86 """
    _md_memory_model = '32bit'
    _md_os = 'windows'
    _md_major = 6
    _md_minor = 4
    _md_build = 9841
    _md_vtype_module = 'volatility.plugins.overlays.windows.win10_x86_vtypes'
