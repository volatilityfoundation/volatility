# Volatility
# Copyright (C) 2008-2011 Volatile Systems
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie.levy@gmail.com>
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

"""
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0 or later
@contact:      jamie.levy@gmail.com
@organization: Volatile Systems
"""

import volatility.commands as commands
import volatility.scan as scan
import volatility.obj as obj
import volatility.utils as utils
import volatility.debug as debug
import struct
import hashlib

try:
    import distorm3
    has_distorm3 = True 
except ImportError:
    has_distorm3 = False

# Partition types taken from Gary Kessler's MBRParser.pl:
#    http://www.garykessler.net/software/index.html
PartitionTypes = {
    0x00:"Empty",
    0x01:"FAT12,CHS",
    0x04:"FAT16 16-32MB,CHS",
    0x05:"Microsoft Extended",
    0x06:"FAT16 32MB,CHS",
    0x07:"NTFS",
    0x0b:"FAT32,CHS",
    0x0c:"FAT32,LBA",
    0x0e:"FAT16, 32MB-2GB,LBA",
    0x0f:"Microsoft Extended, LBA",
    0x11:"Hidden FAT12,CHS",
    0x14:"Hidden FAT16,16-32MB,CHS",
    0x16:"Hidden FAT16,32MB-2GB,CHS",
    0x18:"AST SmartSleep Partition",
    0x1b:"Hidden FAT32,CHS",
    0x1c:"Hidden FAT32,LBA",
    0x1e:"Hidden FAT16,32MB-2GB,LBA",
    0x27:"PQservice",
    0x39:"Plan 9 partition",
    0x3c:"PartitionMagic recovery partition",
    0x42:"Microsoft MBR,Dynamic Disk",
    0x44:"GoBack partition",
    0x51:"Novell",
    0x52:"CP/M",
    0x63:"Unix System V",
    0x64:"PC-ARMOUR protected partition",
    0x82:"Solaris x86 or Linux Swap",
    0x83:"Linux",
    0x84:"Hibernation",
    0x85:"Linux Extended",
    0x86:"NTFS Volume Set",
    0x87:"NTFS Volume Set",
    0x9f:"BSD/OS",
    0xa0:"Hibernation",
    0xa1:"Hibernation",
    0xa5:"FreeBSD",
    0xa6:"OpenBSD",
    0xa8:"Mac OSX",
    0xa9:"NetBSD",
    0xab:"Mac OSX Boot",
    0xaf:"MacOS X HFS",
    0xb7:"BSDI",
    0xb8:"BSDI Swap",
    0xbb:"Boot Wizard hidden",
    0xbe:"Solaris 8 boot partition",
    0xd8:"CP/M-86",
    0xde:"Dell PowerEdge Server utilities (FAT fs)",
    0xdf:"DG/UX virtual disk manager partition",
    0xeb:"BeOS BFS",
    0xee:"EFI GPT Disk",
    0xef:"EFI System Parition",
    0xfb:"VMWare File System",
    0xfc:"VMWare Swap",
}

# Using structures defined in File System Forensic Analysis pg 88+
# boot code is from bytes 0-439 in the partition table
# we should dissassemble
MBR_types = {
    'PARTITION_ENTRY': [ 0x10, {
        'BootableFlag': [0x0, ['char']],   # 0x80 is bootable
        'StartingCHS': [0x1, ['array', 3, ['unsigned char']]],
        'PartitionType': [0x4, ['char']],
        'EndingCHS': [0x5, ['array', 3, ['unsigned char']]],
        'StartingLBA': [0x8, ['unsigned int']],
        'SizeInSectors': [0xc, ['int']],
    }],
    'PARTITION_TABLE': [ 0x200, {
        'DiskSignature': [ 0x1b8, ['array', 4, ['unsigned char']]],
        'Unused': [ 0x1bc, ['unsigned short']],
        'Entry1': [ 0x1be, ['PARTITION_ENTRY']],
        'Entry2': [ 0x1ce, ['PARTITION_ENTRY']],
        'Entry3': [ 0x1de, ['PARTITION_ENTRY']],
        'Entry4': [ 0x1ee, ['PARTITION_ENTRY']],
        'Signature': [0x1fe, ['unsigned short']],
     }]
}

class PARTITION_ENTRY(obj.CType):
    def get_value(self, char):
        padded = "\x00\x00\x00" + str(char)
        val = int(struct.unpack('>I', padded)[0]) 
        return val

    def get_type(self):
        return PartitionTypes.get(self.get_value(self.PartitionType), "Invalid") 

    def is_bootable(self):
        return self.get_value(self.BootableFlag) == 0x80

    def is_bootable_and_used(self):
        return self.is_bootable() and self.is_used()

    def is_valid(self):
        return self.get_type() != "Invalid"

    def is_used(self):
        return self.get_type() != "Empty" and self.is_valid()

    def StartingSector(self):
        return self.StartingCHS[1] % 64

    def StartingCylinder(self):
        return (self.StartingCHS[1] - self.StartingSector()) * 4 + self.StartingCHS[2]

    def EndingSector(self):
        return self.EndingCHS[1] % 64

    def EndingCylinder(self):
        return (self.EndingCHS[1] - self.EndingSector()) * 4 + self.EndingCHS[2]

    def __str__(self):
        processed_entry = ""
        bootable = self.get_value(self.BootableFlag)
        processed_entry = "Boot flag: {0:#x} {1}\n".format(bootable, "(Bootable)" if self.is_bootable() else '')
        processed_entry += "Partition type: {0:#x} ({1})\n".format(self.get_value(self.PartitionType), self.get_type())
        processed_entry += "Starting Sector (LBA): {0:#x} ({0})\n".format(self.StartingLBA)
        processed_entry += "Starting CHS: Cylinder: {0} Head: {1} Sector: {2}\n".format(self.StartingCylinder(),
                            self.StartingCHS[0],
                            self.StartingSector())
        processed_entry += "Ending CHS: Cylinder: {0} Head: {1} Sector: {2}\n".format(self.EndingCylinder(),
                            self.EndingCHS[0],
                            self.EndingSector())
        processed_entry += "Size in sectors: {0:#x} ({0})\n\n".format(self.SizeInSectors)
        return processed_entry



class MbrObjectTypes(obj.ProfileModification):
    def modification(self, profile):
        profile.object_classes.update({
            'PARTITION_ENTRY': PARTITION_ENTRY,
        })
        profile.vtypes.update(MBR_types)


class MBRScanner(scan.BaseScanner):
    checks = [ ] 

    def __init__(self, window_size = 512, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self, window_size)

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset - 0x1fe


class MBRParser(commands.command):
    """ Scans for and parses potential Master Boot Records (MBRs) """
    def __init__(self, config, *args, **kwargs):
        commands.command.__init__(self, config, *args)
        # We have all these options, however another will be added for diffing 
        # when it is more refined
        config.add_option('HEX', short_option = 'H', default = False,
                          help = 'Output HEX of Bootcode instead of default disassembly',
                          action = "store_true")
        config.add_option('HASH', short_option = 'M', default = None,
                          help = "Hash of bootcode (up to RET) to search for", 
                          action = "store", type = "str")
        config.add_option('FULLHASH', short_option = 'F', default = None,
                          help = "Hash of full bootcode to search for", 
                          action = "store", type = "str")
        config.add_option('DISOFFSET', short_option = 'D', default = None,
                          help = "Offset to start disassembly", 
                          action = "store", type = "int")
        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = "Offset of MBR", 
                          action = "store", type = "int")
        config.add_option('CHECK', short_option = 'C', default = False,
                          help = "Check partitions", 
                          action = "store_true")
        self.code_data = ""


    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')
        if not has_distorm3 and not self._config.HEX:
            debug.error("Install distorm3 code.google.com/p/distorm/")
        diff = 0
        if self._config.DISOFFSET:
            diff = self._config.DISOFFSET

        if self._config.OFFSET:
            PARTITION_TABLE = obj.Object('PARTITION_TABLE', vm = address_space,
                               offset = self._config.OFFSET)
            boot_code = address_space.read(self._config.OFFSET + diff, 440 - diff)
            all_zeros = boot_code.count(chr(0)) == len(boot_code)
            if not all_zeros:
                yield self._config.OFFSET, PARTITION_TABLE, boot_code
            else:
                print "Not a valid MBR: Data all zeroed out"
        else:
            scanner = MBRScanner(needles = ['\x55\xaa'])
            for offset in scanner.scan(address_space):
                PARTITION_TABLE = obj.Object('PARTITION_TABLE', vm = address_space,
                               offset = offset)
                boot_code = address_space.read(offset + diff, 440 - diff)
                all_zeros = boot_code.count(chr(0)) == len(boot_code)
                if not all_zeros:
                    yield offset, PARTITION_TABLE, boot_code


    def Hexdump(self, data, given_offset = 0, width = 16):
        for offset in xrange(0, len(data), width):
            row_data = data[offset:offset + width]
            translated_data = [x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
            hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

            yield offset + given_offset, hexdata, translated_data


    def get_disasm_text(self, boot_code, start):
        iterable = distorm3.DecodeGenerator(0, boot_code, distorm3.Decode16Bits)
        ret = ""  
        self.code_data = boot_code
        for (offset, size, instruction, hexdump) in iterable:
            ret += "0x%.8x: %-32s %s\n" % (offset + start, hexdump, instruction)
            if instruction == "RET":
                self.code_data = boot_code[0:offset + size]
                hexstuff = "\n" + "\n".join(["{0:#010x}: {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in self.Hexdump(boot_code[offset + size:], offset + start + size)])
                ret += hexstuff
                break
        return ret

    def render_text(self, outfd, data):
        dis = 0
        if self._config.DISOFFSET:
            dis = self._config.DISOFFSET

        for offset, PARTITION_TABLE, boot_code in data:
            entry1 = PARTITION_TABLE.Entry1.dereference_as('PARTITION_ENTRY')
            entry2 = PARTITION_TABLE.Entry2.dereference_as('PARTITION_ENTRY')
            entry3 = PARTITION_TABLE.Entry3.dereference_as('PARTITION_ENTRY')
            entry4 = PARTITION_TABLE.Entry4.dereference_as('PARTITION_ENTRY')
            have_bootable = entry1.is_bootable_and_used() or entry2.is_bootable_and_used() or entry3.is_bootable_and_used() or entry4.is_bootable_and_used()
            if self._config.CHECK and not have_bootable: 
                # it doesn't really make sense to have a partition that is bootable, but empty or invalid
                # but we only skip MBRs with these types of partitions if we are checking
                continue
            disasm = self.get_disasm_text(boot_code, offset + dis)
            h = hashlib.md5()
            f = hashlib.md5()
            h.update(self.code_data)
            f.update(boot_code)
            if self._config.HASH:
                hash = "{0}".format(h.hexdigest())
                if hash.lower() != self._config.HASH.lower():
                    continue
            elif self._config.FULLHASH:
                hash = "{0}".format(f.hexdigest())
                if hash.lower() != self._config.FULLHASH.lower():
                    continue

            outfd.write("Potential MBR at physical offset: {0:#x}\n".format(offset))
            outfd.write("Disk Signature: {0:02x}-{1:02x}-{2:02x}-{3:02x}\n".format(
                PARTITION_TABLE.DiskSignature[0], 
                PARTITION_TABLE.DiskSignature[1],
                PARTITION_TABLE.DiskSignature[2],
                PARTITION_TABLE.DiskSignature[3]))

            outfd.write("Bootcode md5: {0}\n".format(h.hexdigest()))
            outfd.write("Bootcode (FULL) md5: {0}\n".format(f.hexdigest()))
            if self._config.HEX:
                hexstuff = "\n" + "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in self.Hexdump(boot_code, offset)])
                outfd.write("Bootable code: \n{0} \n".format(hexstuff))
            else:
                outfd.write("Disassembly of Bootable Code:\n{0}\n\n".format(disasm))

            outfd.write("===== Partition Table #1 =====\n")
            outfd.write(str(entry1))

            outfd.write("===== Partition Table #2 =====\n")
            outfd.write(str(entry2))

            outfd.write("===== Partition Table #3 =====\n")
            outfd.write(str(entry3))

            outfd.write("===== Partition Table #4 =====\n")
            outfd.write(str(entry4))
            outfd.write("\n\n")
