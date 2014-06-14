# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# Additional Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

#pylint: disable-msg=C0111

import os, re
import volatility.plugins.common as common
import volatility.win32 as win32
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.cache as cache

class DllList(common.AbstractWindowsCommand, cache.Testable):
    """Print list of loaded dlls for each process"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        cache.Testable.__init__(self)
        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = 'EPROCESS offset (in hex) in the physical address space',
                          action = 'store', type = 'int')

        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')
                            
        config.add_option('NAME', short_option = 'n', default = None, 
                          help = 'Operate on these process names (regex)', 
                          action = 'store', type = 'str')

    def render_text(self, outfd, data):
        for task in data:
            pid = task.UniqueProcessId

            outfd.write("*" * 72 + "\n")
            outfd.write("{0} pid: {1:6}\n".format(task.ImageFileName, pid))

            if task.Peb:
                ## REMOVE this after 2.4, since we have the cmdline plugin now
                outfd.write("Command line : {0}\n".format(str(task.Peb.ProcessParameters.CommandLine or '')))
                if task.IsWow64:
                    outfd.write("Note: use ldrmodules for listing DLLs in Wow64 processes\n")
                outfd.write("{0}\n".format(str(task.Peb.CSDVersion or '')))
                outfd.write("\n")
                self.table_header(outfd,
                                  [("Base", "[addrpad]"),
                                   ("Size", "[addr]"),
                                   ("LoadCount", "[addr]"), 
                                   ("Path", ""),
                                   ])
                for m in task.get_load_modules():
                    self.table_row(outfd, m.DllBase, m.SizeOfImage, m.LoadCount, str(m.FullDllName or ''))
            else:
                outfd.write("Unable to read PEB for task.\n")

    def filter_tasks(self, tasks):
        """ Reduce the tasks based on the user selectable PIDS parameter.

        Returns a reduced list or the full list if config.PIDS not specified.
        """
        
        if self._config.PID is not None:        
            try:
                pidlist = [int(p) for p in self._config.PID.split(',')]
            except ValueError:
                debug.error("Invalid PID {0}".format(self._config.PID))

            pids = [t for t in tasks if t.UniqueProcessId in pidlist]
            if len(pids) == 0:
                debug.error("Cannot find PID {0}. If its terminated or unlinked, use psscan and then supply --offset=OFFSET".format(self._config.PID))
            return pids
            
        if self._config.NAME is not None:
            try:
                name_re = re.compile(self._config.NAME, re.I)
            except re.error:
                debug.error("Invalid name {0}".format(self._config.NAME))
            
            names = [t for t in tasks if name_re.search(str(t.ImageFileName))]
            if len(names) == 0:
                debug.error("Cannot find name {0}. If its terminated or unlinked, use psscan and then supply --offset=OFFSET".format(self._config.NAME))
            return names
                        
        return tasks

    @staticmethod
    def virtual_process_from_physical_offset(addr_space, offset):
        """ Returns a virtual process from a physical offset in memory """
        # Since this is a physical offset, we find the process
        flat_addr_space = utils.load_as(addr_space.get_config(), astype = 'physical')
        flateproc = obj.Object("_EPROCESS", offset, flat_addr_space)
        # then use the virtual address of its first thread to get into virtual land
        # (Note: the addr_space and flat_addr_space use the same config, so should have the same profile)
        tleoffset = addr_space.profile.get_obj_offset("_ETHREAD", "ThreadListEntry")
        ethread = obj.Object("_ETHREAD", offset = flateproc.ThreadListHead.Flink.v() - tleoffset, vm = addr_space)
        # and ask for the thread's process to get an _EPROCESS with a virtual address space
        virtual_process = ethread.owning_process()
        # Sanity check the bounce. See Issue 154. 
        if virtual_process and offset == addr_space.vtop(virtual_process.obj_offset):
            return virtual_process
        return obj.NoneObject("Unable to bounce back from virtual _ETHREAD to virtual _EPROCESS")

    @cache.CacheDecorator(lambda self: "tests/pslist/pid={0}/offset={1}".format(self._config.PID, self._config.OFFSET))
    def calculate(self):
        """Produces a list of processes, or just a single process based on an OFFSET"""
        addr_space = utils.load_as(self._config)

        if self._config.OFFSET != None:
            tasks = [self.virtual_process_from_physical_offset(addr_space, self._config.OFFSET)]
        else:
            tasks = self.filter_tasks(win32.tasks.pslist(addr_space))

        return tasks

class PSList(DllList):
    """ Print all running processes by following the EPROCESS lists """
    def __init__(self, config, *args, **kwargs):
        DllList.__init__(self, config, *args, **kwargs)
        config.add_option("PHYSICAL-OFFSET", short_option = 'P', 
                          default = False, cache_invalidator = False, 
                          help = "Display physical offsets instead of virtual", 
                          action = "store_true")

    def render_text(self, outfd, data):

        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
        self.table_header(outfd,
                          [("Offset{0}".format(offsettype), "[addrpad]"),
                           ("Name", "20s"),
                           ("PID", ">6"),
                           ("PPID", ">6"),
                           ("Thds", ">6"),
                           ("Hnds", ">8"),
                           ("Sess", ">6"),
                           ("Wow64", ">6"),
                           ("Start", "30"),
                           ("Exit", "30")]
                          )

        for task in data:
            # PHYSICAL_OFFSET must STRICTLY only be used in the results.  If it's used for anything else,
            # it needs to have cache_invalidator set to True in the options
            if not self._config.PHYSICAL_OFFSET:
                offset = task.obj_offset
            else:
                offset = task.obj_vm.vtop(task.obj_offset)
            self.table_row(outfd,
                offset,
                task.ImageFileName,
                task.UniqueProcessId,
                task.InheritedFromUniqueProcessId,
                task.ActiveThreads,
                task.ObjectTable.HandleCount,
                task.SessionId,
                task.IsWow64,
                str(task.CreateTime or ''),
                str(task.ExitTime or ''),
                )


# Inherit from files just for the config options (__init__)
class MemMap(DllList):
    """Print the memory map"""

    def render_text(self, outfd, data):
        first = True
        for pid, task, pagedata in data:
            if not first:
                outfd.write("*" * 72 + "\n")

            task_space = task.get_process_address_space()
            outfd.write("{0} pid: {1:6}\n".format(task.ImageFileName, pid))
            first = False

            offset = 0
            if pagedata:
                self.table_header(outfd,
                                  [("Virtual", "[addrpad]"),
                                   ("Physical", "[addrpad]"),
                                   ("Size", "[addr]"),
                                   ("DumpFileOffset", "[addr]")])

                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        self.table_row(outfd, p[0], pa, p[1], offset)
                    #else:
                    #    outfd.write("0x{0:10x} 0x000000     0x{1:12x}\n".format(p[0], p[1]))
                        offset += p[1]
            else:
                outfd.write("Unable to read pages for task.\n")

    @cache.CacheDecorator(lambda self: "tests/memmap/pid={0}/offset={1}".format(self._config.PID, self._config.OFFSET))
    def calculate(self):
        tasks = DllList.calculate(self)

        for task in tasks:
            if task.UniqueProcessId:
                pid = task.UniqueProcessId
                task_space = task.get_process_address_space()
                pages = task_space.get_available_pages()
                yield pid, task, pages

class MemDump(MemMap):
    """Dump the addressable memory for a process"""

    def __init__(self, config, *args, **kwargs):
        MemMap.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump memory')

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for pid, task, pagedata in data:
            outfd.write("*" * 72 + "\n")

            task_space = task.get_process_address_space()
            outfd.write("Writing {0} [{1:6}] to {2}.dmp\n".format(task.ImageFileName, pid, str(pid)))

            f = open(os.path.join(self._config.DUMP_DIR, str(pid) + ".dmp"), 'wb')
            if pagedata:
                for p in pagedata:
                    data = task_space.read(p[0], p[1])
                    if data == None:
                        if self._config.verbose:
                            outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(p[0], task.obj_offset, p[1]))
                    else:
                        f.write(data)
            else:
                outfd.write("Unable to read pages for task.\n")
            f.close()
