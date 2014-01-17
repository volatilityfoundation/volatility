# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

#pylint: disable-msg=C0111

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      bdolangavitt@wesleyan.edu
"""

import volatility.obj as obj
import volatility.addrspace as addrspace
import struct

FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])

CI_TYPE_MASK = 0x80000000
CI_TYPE_SHIFT = 0x1F
CI_TABLE_MASK = 0x7FE00000
CI_TABLE_SHIFT = 0x15
CI_BLOCK_MASK = 0x1FF000
CI_BLOCK_SHIFT = 0x0C
CI_OFF_MASK = 0x0FFF
CI_OFF_SHIFT = 0x0

BLOCK_SIZE = 0x1000

class HiveAddressSpace(addrspace.BaseAddressSpace):
    def __init__(self, base, config, hive_addr, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, config)
        self.base = base
        self.hive = obj.Object("_HHIVE", hive_addr, base)
        self.baseblock = self.hive.BaseBlock.v()
        self.flat = self.hive.Flat.v() > 0

    def __getstate__(self):
        result = addrspace.BaseAddressSpace.__getstate__(self)
        result['hive_addr'] = self.hive.obj_offset

        return result

    def vtop(self, vaddr):
        # If the hive is listed as "flat", it is all contiguous in memory
        # so we can just calculate it relative to the base block.
        if self.flat:
            return self.baseblock + vaddr + BLOCK_SIZE + 4

        ci_type = (vaddr & CI_TYPE_MASK) >> CI_TYPE_SHIFT
        ci_table = (vaddr & CI_TABLE_MASK) >> CI_TABLE_SHIFT
        ci_block = (vaddr & CI_BLOCK_MASK) >> CI_BLOCK_SHIFT
        ci_off = (vaddr & CI_OFF_MASK) >> CI_OFF_SHIFT

        block = self.hive.Storage[ci_type].Map.Directory[ci_table].Table[ci_block].BlockAddress

        return block + ci_off + 4

    #def hentry(self, vaddr):
    #    ci_type = (vaddr & CI_TYPE_MASK) >> CI_TYPE_SHIFT
    #    ci_table = (vaddr & CI_TABLE_MASK) >> CI_TABLE_SHIFT
    #    ci_block = (vaddr & CI_BLOCK_MASK) >> CI_BLOCK_SHIFT
    #    ci_off = (vaddr & CI_OFF_MASK) >> CI_OFF_SHIFT

    #    dir_map = read_obj(self.base, self.types, ['_HHIVE', 'Storage', ci_type, 'Map'],
    #        self.hive)
    #    if not dir_map:
    #        return None
    #    table = read_obj(self.base, self.types, ['_HMAP_DIRECTORY', 'Directory', ci_table],
    #        dir_map)
    #    if not table:
    #        return None
    #    #block = read_obj(self.base, self.types, ['_HMAP_TABLE', 'Table', ci_block, 'BlockAddress'],
    #    #    table)
    #    
    #    return Obj("_HMAP_ENTRY", table, self.base)

    def read(self, vaddr, length, zero = False):
        length = int(length)
        vaddr = int(vaddr)
        first_block = BLOCK_SIZE - vaddr % BLOCK_SIZE
        full_blocks = ((length + (vaddr % BLOCK_SIZE)) / BLOCK_SIZE) - 1
        left_over = (length + vaddr) % BLOCK_SIZE

        paddr = self.vtop(vaddr)
        if paddr == None and zero:
            if length < first_block:
                return "\0" * length
            else:
                stuff_read = "\0" * first_block
        elif paddr == None:
            return None
        else:
            if length < first_block:
                stuff_read = self.base.read(paddr, length)
                if not stuff_read and zero:
                    return "\0" * length
                else:
                    return stuff_read

            stuff_read = self.base.read(paddr, first_block)
            if not stuff_read and zero:
                stuff_read = "\0" * first_block

        new_vaddr = vaddr + first_block
        for _i in range(0, full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * BLOCK_SIZE
            elif paddr == None:
                return None
            else:
                new_stuff = self.base.read(paddr, BLOCK_SIZE)
                if not new_stuff and zero:
                    new_stuff = "\0" * BLOCK_SIZE
                elif not new_stuff:
                    return None
                else:
                    stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + BLOCK_SIZE

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * left_over
            elif paddr == None:
                return None
            else:
                stuff_read = stuff_read + self.base.read(paddr, left_over)
        return stuff_read

    def zread(self, addr, length):
        return self.read(addr, length, True)

    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def is_valid_address(self, addr):
        if not addr:
            return False
        vaddr = self.vtop(addr)
        if not vaddr:
            return False
        return self.base.is_valid_address(vaddr)

    def save(self, outf):
        baseblock = self.base.read(self.baseblock, BLOCK_SIZE)
        if baseblock:
            outf.write(baseblock)
        else:
            outf.write("\0" * BLOCK_SIZE)

        length = self.hive.Storage[0].Length.v()
        for i in range(0, length, BLOCK_SIZE):
            data = None

            paddr = self.vtop(i)
            if paddr:
                paddr = paddr - 4
                data = self.base.read(paddr, BLOCK_SIZE)
            else:
                print "No mapping found for index {0:x}, filling with NULLs".format(i)

            if not data:
                print "Physical layer returned None for index {0:x}, filling with NULL".format(i)
                data = '\0' * BLOCK_SIZE

            outf.write(data)

    def stats(self, stable = True):
        if stable:
            stor = 0
            ci = lambda x: x
        else:
            stor = 1
            ci = lambda x: x | 0x80000000

        length = self.hive.Storage[stor].Length.v()
        total_blocks = length / BLOCK_SIZE
        bad_blocks_reg = 0
        bad_blocks_mem = 0
        for i in range(0, length, BLOCK_SIZE):
            i = ci(i)
            data = None
            paddr = self.vtop(i) - 4

            if paddr:
                data = self.base.read(paddr, BLOCK_SIZE)
            else:
                bad_blocks_reg += 1
                continue

            if not data:
                bad_blocks_mem += 1

        print "{0} bytes in hive.".format(length)
        print "{0} blocks not loaded by CM, {1} blocks paged out, {2} total blocks.".format(bad_blocks_reg, bad_blocks_mem, total_blocks)
        if total_blocks:
            print "Total of {0:.2f}% of hive unreadable.".format(((bad_blocks_reg + bad_blocks_mem) / float(total_blocks)) * 100)

        return (bad_blocks_reg, bad_blocks_mem, total_blocks)


class HiveFileAddressSpace(addrspace.BaseAddressSpace):
    def __init__(self, base, config):
        addrspace.BaseAddressSpace.__init__(self, base, config)
        self.base = base

    def vtop(self, vaddr):
        return vaddr + BLOCK_SIZE + 4

    def read(self, vaddr, length, zero = False):
        first_block = BLOCK_SIZE - vaddr % BLOCK_SIZE
        full_blocks = ((length + (vaddr % BLOCK_SIZE)) / BLOCK_SIZE) - 1
        left_over = (length + vaddr) % BLOCK_SIZE

        paddr = self.vtop(vaddr)
        if paddr == None and zero:
            if length < first_block:
                return "\0" * length
            else:
                stuff_read = "\0" * first_block
        elif paddr == None:
            return None
        else:
            if length < first_block:
                stuff_read = self.base.read(paddr, length)
                if not stuff_read and zero:
                    return "\0" * length
                else:
                    return stuff_read

            stuff_read = self.base.read(paddr, first_block)
            if not stuff_read and zero:
                stuff_read = "\0" * first_block

        new_vaddr = vaddr + first_block
        for _i in range(0, full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * BLOCK_SIZE
            elif paddr == None:
                return None
            else:
                new_stuff = self.base.read(paddr, BLOCK_SIZE)
                if not new_stuff and zero:
                    new_stuff = "\0" * BLOCK_SIZE
                elif not new_stuff:
                    return None
                else:
                    stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + BLOCK_SIZE

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * left_over
            elif paddr == None:
                return None
            else:
                stuff_read = stuff_read + self.base.read(paddr, left_over)
        return stuff_read

    def zread(self, addr, length):
        return self.read(addr, length, True)

    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def is_valid_address(self, vaddr):
        paddr = self.vtop(vaddr)
        if not paddr:
            return False
        return self.base.is_valid_address(paddr)
