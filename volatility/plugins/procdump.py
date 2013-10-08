# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# Additional Authors:
# Mike Auty <mike.auty@gmail.com>
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

import os
import struct
import volatility.plugins.taskmods as taskmods
import volatility.debug as debug
import volatility.obj as obj
import volatility.exceptions as exceptions

class ProcExeDump(taskmods.DllList):
    """Dump a process to an executable file sample"""
    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump executable files')

        config.add_option("UNSAFE", short_option = "u", default = False, action = 'store_true',
                          help = 'Bypasses certain sanity checks when creating image')

    def dump_pe(self, space, base, dump_file):
        """
        Dump a PE from an AS into a file. 
        
        @param space: an AS to use
        @param base: PE base address
        @param dump_file: dumped file name

        @returns a string status message 
        """

        of = open(os.path.join(self._config.DUMP_DIR, dump_file), 'wb')
        try:
            for offset, code in self.get_image(space, base):
                of.seek(offset)
                of.write(code)
            result = "OK: {0}".format(dump_file)
        except ValueError, ve:
            result = "Error: {0}".format(ve)
        except exceptions.SanityCheckException, ve:
            result = "Error: {0} Try -u/--unsafe".format(ve)
        finally:
            of.close()

        return result

    def render_text(self, outfd, data):
        """Renders the tasks to disk images, outputting progress as they go"""
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        self.table_header(outfd,
                          [("Process(V)", "[addrpad]"),
                           ("ImageBase", "[addrpad]"),
                           ("Name", "20"),
                           ("Result", "")])

        for task in data:
            task_space = task.get_process_address_space()
            if task_space == None:
                result = "Error: Cannot acquire process AS"
            elif task.Peb == None:
                # we must use m() here, because any other attempt to 
                # reference task.Peb will try to instantiate the _PEB
                result = "Error: PEB at {0:#x} is paged".format(task.m('Peb'))
            elif task_space.vtop(task.Peb.ImageBaseAddress) == None:
                result = "Error: ImageBaseAddress at {0:#x} is paged".format(task.Peb.ImageBaseAddress)
            else:
                dump_file = "executable." + str(task.UniqueProcessId) + ".exe"
                result = self.dump_pe(task_space,
                                task.Peb.ImageBaseAddress,
                                dump_file)
            self.table_row(outfd,
                            task.obj_offset,
                            task.Peb.ImageBaseAddress,
                            task.ImageFileName,
                            result)

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

    def get_code(self, addr_space, data_start, data_size, offset):
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
                    debug.debug("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(data_start, offset, data_size))
            code += data_read
            return (offset, code)

        data_read = addr_space.zread(data_start, first_block)
        if paddr == None:
            if self._config.verbose:
                debug.debug("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(data_start, offset, first_block))
        code += data_read

        # The middle part of the read
        new_vaddr = data_start + first_block

        for _i in range(0, full_blocks):
            data_read = addr_space.zread(new_vaddr, 0x1000)
            if addr_space.vtop(new_vaddr) == None:
                if self._config.verbose:
                    debug.debug("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(new_vaddr, offset, 0x1000))
            code += data_read
            new_vaddr = new_vaddr + 0x1000

        # The last part of the read
        if left_over > 0:
            data_read = addr_space.zread(new_vaddr, left_over)
            if addr_space.vtop(new_vaddr) == None:
                if self._config.verbose:
                    debug.debug("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(new_vaddr, offset, left_over))
            code += data_read
        return (offset, code)

    def get_image(self, addr_space, base_addr):
        """Outputs an executable disk image of a process"""
        nt_header = self.get_nt_header(addr_space = addr_space,
                                       base_addr = base_addr)

        soh = nt_header.OptionalHeader.SizeOfHeaders
        header = addr_space.zread(base_addr, soh)
        yield (0, header)

        fa = nt_header.OptionalHeader.FileAlignment
        for sect in nt_header.get_sections(self._config.UNSAFE):
            foa = self.round(sect.PointerToRawData, fa)
            if foa != sect.PointerToRawData:
                debug.warning("Section start on disk not aligned to file alignment.\n")
                debug.warning("Adjusted section start from {0} to {1}.\n".format(sect.PointerToRawData, foa))
            yield self.get_code(addr_space,
                                sect.VirtualAddress + base_addr,
                                sect.SizeOfRawData, foa)

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

    def get_image(self, addr_space, base_addr):
        """Outputs an executable memory image of a process"""
        nt_header = self.get_nt_header(addr_space, base_addr)

        sa = nt_header.OptionalHeader.SectionAlignment
        shs = addr_space.profile.get_obj_size('_IMAGE_SECTION_HEADER')

        yield self.get_code(addr_space, base_addr, nt_header.OptionalHeader.SizeOfImage, 0)

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
