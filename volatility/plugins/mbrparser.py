# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie@memoryanalysis.net>
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

"""
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie@memoryanalysis.net
@organization: Volatility Foundation
"""

import volatility.commands as commands
import volatility.scan as scan
import volatility.obj as obj
import volatility.utils as utils
import volatility.debug as debug
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex, Bytes
import struct
import hashlib
import os

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

class MBRParser(commands.Command):
    """ Scans for and parses potential Master Boot Records (MBRs) """
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args)
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
        config.add_option('NOCHECK', short_option = 'N', default = False,
                          help = "Don't check partitions", 
                          action = "store_true")
        config.add_option('DISK', short_option = 'm', default = None,
                         help = "Disk or extracted MBR",
                         action = "store", type = "str")
        config.add_option('MAXDISTANCE', short_option = 'x', default = None,
                         help = "Maximum Levenshtein distance for MBR vs Disk",
                         action = "store", type = "int")
        config.add_option('ZEROSTART', short_option = 'z', default = False,
                          help = 'Start the output header at zero',
                          action = "store_true")
        self.code_data = ""
        self.disk_mbr = None


    # Taken from:
    # http://en.wikibooks.org/wiki/Algorithm_implementation/Strings/Levenshtein_distance#Python
    def levenshtein(self, s1, s2):
        if len(s1) < len(s2):
            return self.levenshtein(s2, s1) 
 
        # len(s1) >= len(s2)
        if len(s2) == 0:
            return len(s1)
 
        previous_row = xrange(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
                deletions = current_row[j] + 1       # than s2
                substitutions = previous_row[j] + (c1 != c2) 
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
 
        return previous_row[-1]

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')
        if not has_distorm3 and not self._config.HEX:
            debug.error("Install distorm3 code.google.com/p/distorm/")
        if self._config.MAXDISTANCE != None and not self._config.DISK:
            debug.error("Must supply the path for the extracted MBR/Disk when using MAXDISTANCE")
        if self._config.DISK and not os.path.isfile(self._config.DISK):
            debug.error(self._config.DISK + " does not exist")

        diff = 0
        if self._config.DISOFFSET:
            diff = self._config.DISOFFSET

        if self._config.DISK:
            file = open(self._config.DISK, "rb")
            self.disk_mbr = file.read(440)
            file.close()

        if self._config.OFFSET:
            PARTITION_TABLE = obj.Object('PARTITION_TABLE', vm = address_space,
                               offset = self._config.OFFSET)
            boot_code = address_space.read(self._config.OFFSET + diff, 440 - diff)
            if boot_code:
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
                if boot_code:
                    all_zeros = boot_code.count(chr(0)) == len(boot_code)
                if not all_zeros:
                    yield offset, PARTITION_TABLE, boot_code


    def Hexdump(self, data, given_offset = 0, width = 16):
        for offset in xrange(0, len(data), width):
            row_data = data[offset:offset + width]
            translated_data = [x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
            hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

            yield offset + given_offset, hexdata, translated_data

    def _get_instructions(self, boot_code):
        if self._config.HEX:
            return "".join(["{2}".format(o, h, ''.join(c)) for o, h, c in self.Hexdump(boot_code, 0)])
        iterable = distorm3.DecodeGenerator(0, boot_code, distorm3.Decode16Bits)
        ret = ""  
        for (offset, size, instruction, hexdump) in iterable:
            ret += "{0}".format(instruction)
            if instruction == "RET":
                hexstuff = "".join(["{2}".format(o, h, ''.join(c)) for o, h, c in self.Hexdump(boot_code[offset + size:], 0)]) 
                ret += hexstuff
                break
        return ret 

    def get_disasm_text(self, boot_code, start):
        iterable = distorm3.DecodeGenerator(0, boot_code, distorm3.Decode16Bits)
        ret = ""  
        self.code_data = boot_code
        for (offset, size, instruction, hexdump) in iterable:
            ret += "{0:010x}: {1:<32} {2}\n".format(offset + start, hexdump, instruction)
            if instruction == "RET":
                self.code_data = boot_code[0:offset + size]
                hexstuff = "\n" + "\n".join(["{0:010x}: {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in self.Hexdump(boot_code[offset + size:], offset + start + size)])
                ret += hexstuff
                break
        return ret

    def unified_output(self, data):
        return TreeGrid([("Offset", Address),
                       ("DiskSignature", str),
                       ("BootMD5", str),
                       ("FullBootMD5", str),
                       ("Distance", int),
                       ("PartABootFlag", str),
                       ("PartAType", str),
                       ("PartALBA", Hex),
                       ("PartAStartCHS", str),
                       ("PartAEndCHS", str),
                       ("PartASectorSize", Hex),
                       ("PartBBootFlag", str),
                       ("PartBType", str),
                       ("PartBLBA", Hex),
                       ("PartBStartCHS", str),
                       ("PartBEndCHS", str),
                       ("PartBSectorSize", Hex),
                       ("PartCBootFlag", str),
                       ("PartCType", str),
                       ("PartCLBA", Hex),
                       ("PartCStartCHS", str),
                       ("PartCEndCHS", str),
                       ("PartCSectorSize", Hex),
                       ("PartDBootFlag", str),
                       ("PartDType", str),
                       ("PartDLBA", Hex),
                       ("PartDStartCHS", str),
                       ("PartDEndCHS", str),
                       ("PartDSectorSize", Hex), 
                       ("Bootcode", Bytes)],
                        self.generator(data))

    def generator(self, data):
        if self._config.DISOFFSET:
            dis = self._config.DISOFFSET

        for offset, PARTITION_TABLE, boot_code in data:
            entry1 = PARTITION_TABLE.Entry1.dereference_as('PARTITION_ENTRY')
            entry2 = PARTITION_TABLE.Entry2.dereference_as('PARTITION_ENTRY')
            entry3 = PARTITION_TABLE.Entry3.dereference_as('PARTITION_ENTRY')
            entry4 = PARTITION_TABLE.Entry4.dereference_as('PARTITION_ENTRY')
            have_bootable = entry1.is_bootable_and_used() or entry2.is_bootable_and_used() or entry3.is_bootable_and_used() or entry4.is_bootable_and_used()
            if not self._config.NOCHECK and not have_bootable: 
                # it doesn't really make sense to have a partition that is bootable, but empty or invalid
                # but we only skip MBRs with these types of partitions if we are checking
                continue

            distance = 0
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
            if self.disk_mbr:
                distance = self.levenshtein(self._get_instructions(self.disk_mbr), self._get_instructions(boot_code))
                if self._config.MAXDISTANCE != None and distance > self._config.MAXDISTANCE:
                    continue

            disksig = "{0:02x}-{1:02x}-{2:02x}-{3:02x}".format(
                PARTITION_TABLE.DiskSignature[0],
                PARTITION_TABLE.DiskSignature[1],
                PARTITION_TABLE.DiskSignature[2],
                PARTITION_TABLE.DiskSignature[3])

            yield (0, [Address(offset),
                  disksig,
                  str(h.hexdigest()),
                  str(f.hexdigest()),
                  int(distance),
                  "{0:#x} {1}".format(entry1.get_value(entry1.BootableFlag), "(Bootable)" if entry1.is_bootable() else ""),
                  "{0:#x} ({1})".format(entry1.get_value(entry1.PartitionType), entry1.get_type()),
                  Hex(entry1.StartingLBA),
                  "Cylinder: {0} Head: {1} Sector: {2}".format(entry1.StartingCylinder(), entry1.StartingCHS[0], entry1.StartingSector()),
                  "Cylinder: {0} Head: {1} Sector: {2}".format(entry1.EndingCylinder(), entry1.EndingCHS[0], entry1.EndingSector()),
                  Hex(entry1.SizeInSectors),
                  "{0:#x} {1}".format(entry2.get_value(entry2.BootableFlag), "(Bootable)" if entry2.is_bootable() else ""), 
                  "{0:#x} ({1})".format(entry2.get_value(entry2.PartitionType), entry2.get_type()),
                  Hex(entry2.StartingLBA),
                  "Cylinder: {0} Head: {1} Sector: {2}".format(entry2.StartingCylinder(), entry2.StartingCHS[0], entry2.StartingSector()),
                  "Cylinder: {0} Head: {1} Sector: {2}".format(entry2.EndingCylinder(), entry2.EndingCHS[0], entry2.EndingSector()),
                  Hex(entry2.SizeInSectors),
                  "{0:#x} {1}".format(entry3.get_value(entry3.BootableFlag), "(Bootable)" if entry3.is_bootable() else ""), 
                  "{0:#x} ({1})".format(entry3.get_value(entry3.PartitionType), entry3.get_type()),
                  Hex(entry3.StartingLBA),
                  "Cylinder: {0} Head: {1} Sector: {2}".format(entry3.StartingCylinder(), entry3.StartingCHS[0], entry3.StartingSector()),
                  "Cylinder: {0} Head: {1} Sector: {2}".format(entry3.EndingCylinder(), entry3.EndingCHS[0], entry3.EndingSector()),
                  Hex(entry3.SizeInSectors),
                  "{0:#x} {1}".format(entry4.get_value(entry4.BootableFlag), "(Bootable)" if entry4.is_bootable() else ""), 
                  "{0:#x} ({1})".format(entry4.get_value(entry4.PartitionType), entry4.get_type()),
                  Hex(entry4.StartingLBA),
                  "Cylinder: {0} Head: {1} Sector: {2}".format(entry4.StartingCylinder(), entry4.StartingCHS[0], entry4.StartingSector()),
                  "Cylinder: {0} Head: {1} Sector: {2}".format(entry4.EndingCylinder(), entry4.EndingCHS[0], entry4.EndingSector()),
                  Hex(entry4.SizeInSectors),
                  Bytes(boot_code)])
                       

    def render_text(self, outfd, data):
        border = "*" * 75
        dis = 0
        if self._config.DISOFFSET:
            dis = self._config.DISOFFSET

        for offset, PARTITION_TABLE, boot_code in data:
            entry1 = PARTITION_TABLE.Entry1.dereference_as('PARTITION_ENTRY')
            entry2 = PARTITION_TABLE.Entry2.dereference_as('PARTITION_ENTRY')
            entry3 = PARTITION_TABLE.Entry3.dereference_as('PARTITION_ENTRY')
            entry4 = PARTITION_TABLE.Entry4.dereference_as('PARTITION_ENTRY')
            have_bootable = entry1.is_bootable_and_used() or entry2.is_bootable_and_used() or entry3.is_bootable_and_used() or entry4.is_bootable_and_used()
            if not self._config.NOCHECK and not have_bootable: 
                # it doesn't really make sense to have a partition that is bootable, but empty or invalid
                # but we only skip MBRs with these types of partitions if we are checking
                continue
            disasm = ""
            distance = 0
            start = offset
            boot_code_output = ""
            if self._config.ZEROSTART:
                start = 0
            if not self._config.HEX:
                disasm = self.get_disasm_text(boot_code, start + dis)
                if disasm == "" or self.code_data == None:
                    continue
                boot_code_output = "Disassembly of Bootable Code:\n{0}\n\n".format(disasm)
            else:
                hexstuff = "\n" + "\n".join(["{0:010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in self.Hexdump(boot_code, start)])
                boot_code_output = "Bootable code: \n{0} \n\n".format(hexstuff)
                
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
            if self.disk_mbr:
                distance = self.levenshtein(self._get_instructions(self.disk_mbr), self._get_instructions(boot_code))
                if self._config.MAXDISTANCE != None and distance > self._config.MAXDISTANCE:
                    continue

            outfd.write("{0}\n".format(border))
            outfd.write("Potential MBR at physical offset: {0:#x}\n".format(offset))
            outfd.write("Disk Signature: {0:02x}-{1:02x}-{2:02x}-{3:02x}\n".format(
                PARTITION_TABLE.DiskSignature[0], 
                PARTITION_TABLE.DiskSignature[1],
                PARTITION_TABLE.DiskSignature[2],
                PARTITION_TABLE.DiskSignature[3]))

            outfd.write("Bootcode md5: {0}\n".format(h.hexdigest()))
            outfd.write("Bootcode (FULL) md5: {0}\n".format(f.hexdigest()))
            if self.disk_mbr:
                outfd.write("\nLevenshtein Distance from Supplied MBR: {0}\n\n".format(distance))

            outfd.write(boot_code_output)

            outfd.write("===== Partition Table #1 =====\n")
            outfd.write(str(entry1))

            outfd.write("===== Partition Table #2 =====\n")
            outfd.write(str(entry2))

            outfd.write("===== Partition Table #3 =====\n")
            outfd.write(str(entry3))

            outfd.write("===== Partition Table #4 =====\n")
            outfd.write(str(entry4))
            outfd.write("{0}\n\n".format(border))
