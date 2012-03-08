# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# Additional Authors:
# Mike Auty <mike.auty@gmail.com>
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

import os
import struct
import volatility.plugins.taskmods as taskmods
import volatility.debug as debug
import volatility.obj as obj

class ProcExeDump(taskmods.DllList):
    """Dump a process to an executable file sample"""
    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump executable files')

        config.add_option("UNSAFE", short_option = "u", default = False, action = 'store_true',
                          help = 'Bypasses certain sanity checks when creating image')

    def render_text(self, outfd, data):
        """Renders the tasks to disk images, outputting progress as they go"""
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for task in data:
            pid = task.UniqueProcessId
            outfd.write("*" * 72 + "\n")
            task_space = task.get_process_address_space()
            if task.Peb == None:
                outfd.write("Error: PEB not memory resident for process [{0}]\n".format(pid))
                continue
            if task.Peb.ImageBaseAddress == None or task_space == None or task_space.vtop(task.Peb.ImageBaseAddress) == None:
                outfd.write("Error: ImageBaseAddress not memory resident for process [{0}]\n".format(pid))
                continue
            outfd.write("Dumping {0}, pid: {1:6} output: {2}\n".format(task.ImageFileName, pid, "executable." + str(pid) + ".exe"))
            of = open(os.path.join(self._config.DUMP_DIR, "executable." + str(pid) + ".exe"), 'wb')
            try:
                for chunk in self.get_image(outfd, task.get_process_address_space(), task.Peb.ImageBaseAddress):
                    offset, code = chunk
                    of.seek(offset)
                    of.write(code)
            except ValueError, ve:
                outfd.write("Unable to dump executable; sanity check failed:\n")
                outfd.write("  " + str(ve) + "\n")
                outfd.write("You can use -u to disable this check.\n")
            of.close()

    def round(self, addr, align, up = False):
        """Rounds down an address based on an alignment"""
        if addr % align == 0:
            return addr
        else:
            if up:
                return (addr + (align - (addr % align)))
            return (addr - (addr % align))

    def get_nt_header(self, addr_space, base_addr):
        """Returns the NT Header object for a task"""

        dos_header = obj.Object("_IMAGE_DOS_HEADER", offset = base_addr,
                                vm = addr_space)

        return dos_header.get_nt_header()

    def get_code(self, addr_space, data_start, data_size, offset, outfd):
        """Returns a single section of re-created data from a file image"""
        first_block = 0x1000 - data_start % 0x1000
        full_blocks = ((data_size + (data_start % 0x1000)) / 0x1000) - 1
        left_over = (data_size + data_start) % 0x1000

        paddr = addr_space.vtop(data_start)
        code = ""

        # Deal with reads that are smaller than a block
        if data_size < first_block:
            data_read = addr_space.zread(data_start, data_size)
            if paddr == None:
                if self._config.verbose:
                    outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(data_start, offset, data_size))
            code += data_read
            return (offset, code)

        data_read = addr_space.zread(data_start, first_block)
        if paddr == None:
            if self._config.verbose:
                outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(data_start, offset, first_block))
        code += data_read

        # The middle part of the read
        new_vaddr = data_start + first_block

        for _i in range(0, full_blocks):
            data_read = addr_space.zread(new_vaddr, 0x1000)
            if addr_space.vtop(new_vaddr) == None:
                if self._config.verbose:
                    outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(new_vaddr, offset, 0x1000))
            code += data_read
            new_vaddr = new_vaddr + 0x1000

        # The last part of the read
        if left_over > 0:
            data_read = addr_space.zread(new_vaddr, left_over)
            if addr_space.vtop(new_vaddr) == None:
                if self._config.verbose:
                    outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(new_vaddr, offset, left_over))
            code += data_read
        return (offset, code)

    def get_image(self, outfd, addr_space, base_addr):
        """Outputs an executable disk image of a process"""
        nt_header = self.get_nt_header(addr_space = addr_space,
                                       base_addr = base_addr)

        soh = nt_header.OptionalHeader.SizeOfHeaders
        header = addr_space.read(base_addr, soh)
        yield (0, header)

        fa = nt_header.OptionalHeader.FileAlignment
        for sect in nt_header.get_sections(self._config.UNSAFE):
            foa = self.round(sect.PointerToRawData, fa)
            if foa != sect.PointerToRawData:
                outfd.write("Warning: section start on disk not aligned to file alignment.\n")
                outfd.write("Warning: adjusted section start from {0} to {1}.\n".format(sect.PointerToRawData, foa))
            yield self.get_code(addr_space,
                                sect.VirtualAddress + base_addr,
                                sect.SizeOfRawData, foa, outfd)

class ProcMemDump(ProcExeDump):
    """Dump a process to an executable memory sample"""

    def replace_header_field(self, sect, header, item, value):
        """Replaces a field in a sector header"""
        field_size = item.size()
        start = item.obj_offset - sect.obj_offset
        end = start + field_size
        newval = struct.pack(item.format_string, int(value))
        result = header[:start] + newval + header[end:]
        return result

    def get_image(self, outfd, addr_space, base_addr):
        """Outputs an executable memory image of a process"""
        nt_header = self.get_nt_header(addr_space, base_addr)

        sa = nt_header.OptionalHeader.SectionAlignment
        shs = addr_space.profile.get_obj_size('_IMAGE_SECTION_HEADER')

        yield self.get_code(addr_space, base_addr, nt_header.OptionalHeader.SizeOfImage, 0, outfd)

        prevsect = None
        sect_sizes = []
        for sect in nt_header.get_sections(self._config.UNSAFE):
            if prevsect is not None:
                sect_sizes.append(sect.VirtualAddress - prevsect.VirtualAddress)
            prevsect = sect
        if prevsect is not None:
            sect_sizes.append(self.round(prevsect.Misc.VirtualSize, sa, up = True))

        counter = 0
        start_addr = nt_header.FileHeader.SizeOfOptionalHeader + (nt_header.OptionalHeader.obj_offset - base_addr)
        for sect in nt_header.get_sections(self._config.UNSAFE):
            sectheader = addr_space.read(sect.obj_offset, shs)
            # Change the PointerToRawData
            sectheader = self.replace_header_field(sect, sectheader, sect.PointerToRawData, sect.VirtualAddress)
            sectheader = self.replace_header_field(sect, sectheader, sect.SizeOfRawData, sect_sizes[counter])
            sectheader = self.replace_header_field(sect, sectheader, sect.Misc.VirtualSize, sect_sizes[counter])

            yield (start_addr + (counter * shs), sectheader)
            counter += 1
