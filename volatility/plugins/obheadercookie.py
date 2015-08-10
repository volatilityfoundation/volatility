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

import volatility.obj as obj 
import volatility.win32.tasks as tasks 
import volatility.debug as debug

try:
    import distorm3
    has_distorm = True
except ImportError:
    has_distorm = False

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