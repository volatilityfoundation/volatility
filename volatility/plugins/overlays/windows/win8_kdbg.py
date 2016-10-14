# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
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

import struct, copy
import volatility.obj as obj
import volatility.addrspace as addrspace
import volatility.constants as constants
import volatility.utils as utils
import volatility.plugins.overlays.windows.win8 as win8
import volatility.plugins.patchguard as patchguard
import volatility.registry as registry

try:
    import distorm3
    has_distorm = True
except ImportError:
    has_distorm = False

class VolatilityKDBG(obj.VolatilityMagic):
    """A Scanner for KDBG data within an address space. 

    This implementation is specific for Windows 8 / 2012 
    64-bit versions because the KDBG block is encoded. We 
    have to find it a special way and then perform the 
    decoding routine before Volatility plugins can run. 
    """

    def v(self):
        """The --kdbg parameter for this Win8/2012 KDBG 
        structure is the virtual address of the 
        nt!KdCopyDataBlock function (see kdbgscan output).
        """

        if self.value is None:
            return self.get_best_suggestion()
        else:
            return self.copy_data_block(self.value)

    def get_suggestions(self):
        if self.value:
            yield self.copy_data_block(self.value)
        for x in self.generate_suggestions():
            yield x

    def decode_kdbg(self, vals):
        """Decoder the KDBG block using the provided 
        magic values and the algorithm reversed from 
        the Windows kernel file."""

        block_encoded, kdbg_block, wait_never, wait_always = vals
        # just take the maximum. if we decode a tiny bit of 
        # extra data in some cases, its totally fine.
        kdbg_size = max(self.unique_sizes())
        buffer = ""

        entries = obj.Object("Array", 
                            targetType = "unsigned long long", 
                            count = kdbg_size / 8, 
                            offset = kdbg_block, vm = self.obj_vm)

        for entry in entries: 
            low_byte = (wait_never & 0xFFFFFFFF) & 0xFF
            entry = patchguard.rol(entry ^ wait_never, low_byte)
            swap_xor = block_encoded.obj_offset | 0xFFFF000000000000
            entry = patchguard.bswap(entry ^ swap_xor)
            buffer += struct.pack("Q", entry ^ wait_always) 

        return buffer

    def unique_sizes(self):
    
        items = registry.get_plugin_classes(obj.Profile).items()
        sizes = set()
        
        for name, cls in items:
            if (cls._md_os != "windows" or cls._md_memory_model != "64bit"):
                continue
                
            #if (cls._md_major, cls._md_minor) < (6, 2):
            #    continue 
                
            conf = copy.deepcopy(self.obj_vm.get_config())
            conf.PROFILE = name 
            buff = addrspace.BufferAddressSpace(config = conf)
            header = obj.VolMagic(buff).KDBGHeader.v()
            
            # this unpacks the kdbgsize from the signature 
            size = struct.unpack("<H", header[-2:])[0]
            sizes.add(size)
            
        return sizes

    def copy_data_block(self, full_addr):
        """This function emulates nt!KdCopyDataBlock on a live 
        machine by finding the encoded KDBG structure and using
        the required entropy values to decode it."""

        sizes = self.unique_sizes()
        alignment = 8 
        addr_space = self.obj_vm
        bits = distorm3.Decode64Bits

        # nt!KdCopyDataBlock is about 100 bytes, we don't want to read
        # too little and truncate the function, but too much will reach
        # into other function's space
        code = addr_space.read(full_addr, 300)

        # potentially we crossed a boundary into swapped or unallocated space
        if code == None:
            return obj.NoneObject("Crossed a code boundary")

        found_size = False 
        
        for size in sizes:
            val = struct.pack("I", size / alignment)
            if code.find(val) != -1:
                found_size = True
                break
        
        if not found_size:
            return obj.NoneObject("Cannot find KDBG size signature")

        version = (addr_space.profile.metadata.get('major', 0), addr_space.profile.metadata.get('minor', 0))
        if version < (6, 4):
            # we don't perform this check for Windows 10.x
            found_str = False 
            
            for size in sizes:
                val = struct.pack("I", size)
                if code.find(val) != -1:
                    found_str = True
                    break
                
            if not found_str:
                return obj.NoneObject("Cannot find KDBG size signature")  

        ops = list(distorm3.Decompose(full_addr, code, bits))

        # nt!KdDebuggerDataBlock
        kdbg_block = None
        # nt!KiWaitNever
        wait_never = None
        # nt!KiWaitAlways
        wait_always = None
        # nt!KdpDataBlockEncoded
        block_encoded = None

        for op in ops:
            # cmp cs:KdpDataBlockEncoded, 0
            if (not block_encoded and op.mnemonic == "CMP" and 
                        op.operands[0].type == "AbsoluteMemory" and 
                        op.operands[1].type == "Immediate" and 
                        op.operands[1].value == 0):
                # an x64 RIP turned absolute 
                offset = op.address + op.size + op.operands[0].disp
                block_encoded = obj.Object("unsigned char", 
                                        offset = offset,
                                        vm = addr_space)
            # lea rdx, KdDebuggerDataBlock
            elif (not kdbg_block and op.mnemonic == "LEA" and 
                        op.operands[0].type == "Register" and 
                        op.operands[0].size == 64 and 
                        op.operands[1].type == "AbsoluteMemory" and 
                        op.operands[1].dispSize == 32):
                kdbg_block = op.address + op.size + op.operands[1].disp 
            # mov r10, cs:KiWaitNever
            elif (not wait_never and op.mnemonic == "MOV" and 
                        op.operands[0].type == "Register" and 
                        op.operands[0].size == 64 and 
                        op.operands[1].type == "AbsoluteMemory" and 
                        op.operands[1].dispSize == 32):
                offset = op.address + op.size + op.operands[1].disp
                wait_never = obj.Object("unsigned long long", 
                                        offset = offset, 
                                        vm = addr_space)
            # mov r11, cs:KiWaitAlways (Win 8 x64)
            # xor rdx, cs:KiWaitAlways (Win 8.1 x64)
            elif (not wait_always and op.mnemonic in ["MOV", "XOR"] and 
                        op.operands[0].type == "Register" and 
                        op.operands[0].size == 64 and 
                        op.operands[1].type == "AbsoluteMemory" and 
                        op.operands[1].dispSize == 32):
                offset = op.address + op.size + op.operands[1].disp
                wait_always = obj.Object("unsigned long long", 
                                        offset = offset,
                                        vm = addr_space)
                break
            elif op.mnemonic == "RET":
                break

        # check if we've found all the required offsets 
        if (block_encoded != None 
                    and kdbg_block != None 
                    and wait_never != None 
                    and wait_always != None):
            
            # some acquisition tools decode the KDBG block but leave 
            # nt!KdpDataBlockEncoded set, so we handle it here. 
            tag_offset = addr_space.profile.get_obj_offset("_DBGKD_DEBUG_DATA_HEADER64", "OwnerTag")
            signature = addr_space.read(kdbg_block + tag_offset, 4)

            if block_encoded == 1 and signature != "KDBG":
                vals = block_encoded, kdbg_block, wait_never, wait_always
                data = self.decode_kdbg(vals)
                buff = addrspace.BufferAddressSpace(
                            config = addr_space.get_config(),
                            base_offset = kdbg_block,
                            data = data)
                kdbg = obj.Object("_KDDEBUGGER_DATA64", 
                            offset = kdbg_block, 
                            vm = buff, 
                            native_vm = addr_space)
            else:
                kdbg = obj.Object("_KDDEBUGGER_DATA64", 
                            offset = kdbg_block, 
                            vm = addr_space)

            kdbg.newattr('KdCopyDataBlock', full_addr)
            kdbg.newattr('block_encoded', block_encoded == 1 and signature != "KDBG")
            kdbg.newattr('wait_never', wait_never)
            kdbg.newattr('wait_always', wait_always)                    

            return kdbg
        else:
            return obj.NoneObject("Cannot find decoding entropy values")

    def generate_suggestions(self):
        """Generates a list of possible KDBG structure locations"""

        if not has_distorm:
            raise StopIteration("The distorm3 Python library is required")

        overlap = 20
        offset = 0 
        current_offset = offset
        addr_space = self.obj_vm
        
        addresses = sorted(addr_space.get_available_addresses())
        for (range_start, range_size) in addresses:
            # Jump to the next available point to scan from
            current_offset = max(range_start, current_offset)
            range_end = range_start + range_size

            if current_offset < 0xf80000000000:
                continue

            while (current_offset < range_end):
                # Figure out how much data to read
                l = min(constants.SCAN_BLOCKSIZE + overlap, range_end - current_offset)

                data = addr_space.zread(current_offset, l)
            
                for addr in utils.iterfind(data, "\x80\x3D"):
                    full_addr = addr + current_offset 
                    result = self.copy_data_block(full_addr)
                    if result:
                        yield result

                current_offset += min(constants.SCAN_BLOCKSIZE, l)

class Win8x64VolatilityKDBG(obj.ProfileModification):
    """Apply the KDBG finder for x64"""

    before = ['WindowsOverlay', 'WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 2, 
                  'memory_model': lambda x: x == "64bit"}
    
    def modification(self, profile):
        profile.object_classes.update({"VolatilityKDBG": VolatilityKDBG})