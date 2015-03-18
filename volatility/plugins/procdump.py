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

import os
import struct
from volatility import renderers
from volatility.commands import Command
import volatility.plugins.taskmods as taskmods
import volatility.debug as debug
import volatility.obj as obj
import volatility.exceptions as exceptions
from volatility.renderers.basic import Address


class ProcDump(taskmods.DllList):
    """Dump a process to an executable file sample"""
    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump executable files')

        config.add_option("UNSAFE", short_option = "u", default = False, action = 'store_true',
                          help = 'Bypasses certain sanity checks when creating image')
        config.add_option("MEMORY", short_option = "m", default = False, action = 'store_true',
                          help = "Carve as a memory sample rather than exe/disk")
        config.add_option('FIX', short_option = 'x', default = False,
                          help = 'Modify the image base of the dump to the in-memory base address',
                          action = 'store_true')

    def dump_pe(self, space, base, dump_file):
        """
        Dump a PE from an AS into a file.

        @param space: an AS to use
        @param base: PE base address
        @param dump_file: dumped file name

        @returns a string status message
        """

        of = open(os.path.join(self._config.DUMP_DIR, dump_file), 'wb')

        pe_file = obj.Object("_IMAGE_DOS_HEADER", offset = base, vm = space)

        try:
            for offset, code in pe_file.get_image(unsafe = self._config.UNSAFE,
                                                  memory = self._config.MEMORY,
                                                  fix = self._config.FIX):
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

    def calculate(self):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        return taskmods.DllList.calculate(self)

    def unified_output(self, data):
        """Renders the tasks to disk images, outputting progress as they go"""
        return renderers.TreeGrid(
                          [("Process(V)", Address),
                           ("ImageBase", Address),
                           ("Name", str),
                           ("Result", str)],
                          self.generator(data))

    def generator(self, data):
        for task in data:
            task_space = task.get_process_address_space()
            if task_space == None:
                result = "Error: Cannot acquire process AS"
            elif task.Peb == None:
                # we must use m() here, because any other attempt to
                # reference task.Peb will try to instantiate the _PEB
                result = "Error: PEB at {0:#x} is unavailable (possibly due to paging)".format(task.m('Peb'))
            elif task_space.vtop(task.Peb.ImageBaseAddress) == None:
                result = "Error: ImageBaseAddress at {0:#x} is unavailable (possibly due to paging)".format(task.Peb.ImageBaseAddress)
            else:
                dump_file = "executable." + str(task.UniqueProcessId) + ".exe"
                result = self.dump_pe(task_space,
                                task.Peb.ImageBaseAddress,
                                dump_file)
            yield (0,
                            [Address(task.obj_offset),
                            Address(task.Peb.ImageBaseAddress),
                            str(task.ImageFileName),
                            str(result)])

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
                result = "Error: PEB at {0:#x} is unavailable (possibly due to paging)".format(task.m('Peb'))
            elif task_space.vtop(task.Peb.ImageBaseAddress) == None:
                result = "Error: ImageBaseAddress at {0:#x} is unavailable (possibly due to paging)".format(task.Peb.ImageBaseAddress)
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
