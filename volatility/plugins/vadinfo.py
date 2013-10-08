# Volatility
# Copyright (C) 2007-2013 Volatility Foundation  
#
# Authors:
# Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
# The source code in this file was inspired by the excellent work of
# Brendan Dolan-Gavitt. Background information can be found in 
# the following reference:
# "The VAD Tree: A Process-Eye View of Physical Memory," Brendan Dolan-Gavitt

import os.path
import volatility.plugins.taskmods as taskmods
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.constants as constants

# Vad Protections. Also known as page protections. _MMVAD_FLAGS.Protection,
# 3-bits, is an index into nt!MmProtectToValue (the following list). 
PROTECT_FLAGS = dict(enumerate([
    'PAGE_NOACCESS',
    'PAGE_READONLY',
    'PAGE_EXECUTE',
    'PAGE_EXECUTE_READ',
    'PAGE_READWRITE',
    'PAGE_WRITECOPY',
    'PAGE_EXECUTE_READWRITE',
    'PAGE_EXECUTE_WRITECOPY',
    'PAGE_NOACCESS',
    'PAGE_NOCACHE | PAGE_READONLY',
    'PAGE_NOCACHE | PAGE_EXECUTE',
    'PAGE_NOCACHE | PAGE_EXECUTE_READ',
    'PAGE_NOCACHE | PAGE_READWRITE',
    'PAGE_NOCACHE | PAGE_WRITECOPY',
    'PAGE_NOCACHE | PAGE_EXECUTE_READWRITE',
    'PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY',
    'PAGE_NOACCESS',
    'PAGE_GUARD | PAGE_READONLY',
    'PAGE_GUARD | PAGE_EXECUTE',
    'PAGE_GUARD | PAGE_EXECUTE_READ',
    'PAGE_GUARD | PAGE_READWRITE',
    'PAGE_GUARD | PAGE_WRITECOPY',
    'PAGE_GUARD | PAGE_EXECUTE_READWRITE',
    'PAGE_GUARD | PAGE_EXECUTE_WRITECOPY',
    'PAGE_NOACCESS',
    'PAGE_WRITECOMBINE | PAGE_READONLY',
    'PAGE_WRITECOMBINE | PAGE_EXECUTE',
    'PAGE_WRITECOMBINE | PAGE_EXECUTE_READ',
    'PAGE_WRITECOMBINE | PAGE_READWRITE',
    'PAGE_WRITECOMBINE | PAGE_WRITECOPY',
    'PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE',
    'PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY',
]))

# Vad Types. The _MMVAD_SHORT.u.VadFlags (_MMVAD_FLAGS) struct on XP has  
# individual flags, 1-bit each, for these types. The _MMVAD_FLAGS for all
# OS after XP has a member _MMVAD_FLAGS.VadType, 3-bits, which is an index
# into the following enumeration. 
MI_VAD_TYPE = dict(enumerate([
    'VadNone',
    'VadDevicePhysicalMemory',
    'VadImageMap',
    'VadAwe',
    'VadWriteWatch',
    'VadLargePages',
    'VadRotatePhysical',
    'VadLargePageSection',
]))

# Inherit from dlllist just for the config options (__init__)
class VADInfo(taskmods.DllList):
    """Dump the VAD info"""

    def render_text(self, outfd, data):
        for task in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            for vad in task.VadRoot.traverse():
                if vad == None:
                    outfd.write("Error: {0}".format(vad))
                else:
                    self.write_vad_short(outfd, vad)
                    try:
                        self.write_vad_control(outfd, vad)
                    except AttributeError:
                        pass
                    try:
                        self.write_vad_ext(outfd, vad)
                    except AttributeError:
                        pass

                outfd.write("\n")

    def write_vad_short(self, outfd, vad):
        """Renders a text version of a Short Vad"""
        self.table_header(None,
                          [("VAD node @", str(len("VAD node @"))),
                           ("address", "[addrpad]"),
                           ("Start", "5"),
                           ("startaddr", "[addrpad]"),
                           ("End", "3"),
                           ("endaddr", "[addrpad]"),
                           ("Tag", "3"),
                           ("tagval", ""),
                           ])
        self.table_row(outfd, "VAD node @",
                              vad.obj_offset,
                              "Start",
                              vad.Start,
                              "End",
                              vad.End,
                              "Tag",
                              vad.Tag)
        outfd.write("Flags: {0}\n".format(str(vad.u.VadFlags)))
        # although the numeric value of Protection is printed above with VadFlags,
        # let's show the user a human-readable translation of the protection 
        outfd.write("Protection: {0}\n".format(PROTECT_FLAGS.get(vad.u.VadFlags.Protection.v(), hex(vad.u.VadFlags.Protection))))
        # translate the vad type if its available (> XP)
        if hasattr(vad.u.VadFlags, "VadType"):
            outfd.write("Vad Type: {0}\n".format(MI_VAD_TYPE.get(vad.u.VadFlags.VadType.v(), hex(vad.u.VadFlags.VadType))))

    def write_vad_control(self, outfd, vad):
        """Renders a text version of a (non-short) Vad's control information"""

        # even if the ControlArea is not NULL, it is only meaningful 
        # for shared (non private) memory sections. 
        if vad.u.VadFlags.PrivateMemory == 1:
            return

        control_area = vad.ControlArea
        if not control_area:
            return

        outfd.write("ControlArea @{0:08x} Segment {1:08x}\n".format(control_area.dereference().obj_offset, control_area.Segment))
        outfd.write("Dereference list: Flink {0:08x}, Blink {1:08x}\n".format(control_area.DereferenceList.Flink, control_area.DereferenceList.Blink))
        outfd.write("NumberOfSectionReferences: {0:10} NumberOfPfnReferences:  {1:10}\n".format(control_area.NumberOfSectionReferences, control_area.NumberOfPfnReferences))
        outfd.write("NumberOfMappedViews:       {0:10} NumberOfUserReferences: {1:10}\n".format(control_area.NumberOfMappedViews, control_area.NumberOfUserReferences))
        outfd.write("WaitingForDeletion Event:  {0:08x}\n".format(control_area.WaitingForDeletion))
        outfd.write("Control Flags: {0}\n".format(str(control_area.u.Flags)))

        file_object = vad.FileObject

        if file_object:
            outfd.write("FileObject @{0:08x}, Name: {1}\n".format(file_object.obj_offset, str(file_object.FileName or '')))

    def write_vad_ext(self, outfd, vad):
        """Renders a text version of a Long Vad"""
        outfd.write("First prototype PTE: {0:08x} Last contiguous PTE: {1:08x}\n".format(vad.FirstPrototypePte, vad.LastContiguousPte))
        outfd.write("Flags2: {0}\n".format(str(vad.u2.VadFlags2)))

class VADTree(VADInfo):
    """Walk the VAD tree and display in tree format"""

    def render_text(self, outfd, data):
        for task in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            levels = {}
            self.table_header(None,
                              [("indent", ""),
                               ("Start", "[addrpad]"),
                               ("-", "1"),
                               ("End", "[addrpad]")
                              ])
            for vad in task.VadRoot.traverse():
                if vad:
                    level = levels.get(vad.Parent.obj_offset, -1) + 1
                    levels[vad.obj_offset] = level
                    self.table_row(outfd,
                                   " " * level,
                                   vad.Start,
                                   "-",
                                   vad.End)

    def render_dot(self, outfd, data):
        for task in data:
            outfd.write("/" + "*" * 72 + "/\n")
            outfd.write("/* Pid: {0:6} */\n".format(task.UniqueProcessId))
            outfd.write("digraph processtree {\n")
            outfd.write("graph [rankdir = \"TB\"];\n")
            for vad in task.VadRoot.traverse():
                if vad:
                    if vad.Parent:
                        outfd.write("vad_{0:08x} -> vad_{1:08x}\n".format(vad.Parent.obj_offset or 0, vad.obj_offset))
                        outfd.write("vad_{0:08x} [label = \"{{ {1}\\n{2:08x} - {3:08x} }}\""
                                "shape = \"record\" color = \"blue\"];\n".format(
                        vad.obj_offset,
                        vad.Tag,
                        vad.Start,
                        vad.End))

            outfd.write("}\n")

class VADWalk(VADInfo):
    """Walk the VAD tree"""

    def render_text(self, outfd, data):
        for task in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            self.table_header(outfd,
                              [("Address", "[addrpad]"),
                               ("Parent", "[addrpad]"),
                               ("Left", "[addrpad]"),
                               ("Right", "[addrpad]"),
                               ("Start", "[addrpad]"),
                               ("End", "[addrpad]"),
                               ("Tag", "4"),
                               ])
            for vad in task.VadRoot.traverse():
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad:
                    self.table_row(outfd,
                        vad.obj_offset,
                        vad.Parent.obj_offset or 0,
                        vad.LeftChild.dereference().obj_offset or 0,
                        vad.RightChild.dereference().obj_offset or 0,
                        vad.Start,
                        vad.End,
                        vad.Tag)

class VADDump(VADInfo):
    """Dumps out the vad sections to a file"""

    def __init__(self, config, *args, **kwargs):
        VADInfo.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump the VAD files')
        config.add_option('BASE', short_option = 'b', default = None,
                          help = 'Dump VAD with BASE address (in hex)',
                          action = 'store', type = 'int')

    def dump_vad(self, path, vad, address_space):
        """
        Dump an MMVAD to a file. 

        @param path: full path to output file 
        @param vad: an MMVAD object
        @param address_space: process AS for the vad

        The purpose of this function is to read medium
        sized vad chunks and write them immediately to 
        a file, rather than building a large buffer in 
        memory and then flushing it at once. This prevents
        our own analysis process from consuming massive
        amounts of memory for large vads. 

        @returns path to the image file on success or
        an error message stating why the file could not
        be dumped. 
        """

        fh = open(path, "wb")
        if fh:
            offset = vad.Start
            out_of_range = vad.Start + vad.Length 
            while offset < out_of_range:
                to_read = min(constants.SCAN_BLOCKSIZE, out_of_range - offset)
                data = address_space.zread(offset, to_read)
                if not data: 
                    break
                fh.write(data)
                offset += to_read
            fh.close()
            return path
        else:
            return "Cannot open {0} for writing".format(path)
        
    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        self.table_header(outfd,
                          [("Pid", "10"),
                           ("Process", "20"),
                           ("Start", "[addrpad]"),
                           ("End", "[addrpad]"),
                           ("Result", ""),
                           ])

        for task in data:
            # Walking the VAD tree can be done in kernel AS, but to 
            # carve the actual data, we need a valid process AS. 
            task_space = task.get_process_address_space()
            if not task_space:
                outfd.write("Unable to get process AS for {0}\n".format(task.UniqueProcessId))
                continue

            offset = task_space.vtop(task.obj_offset)

            for vad in task.VadRoot.traverse():
                if not vad.is_valid():
                    continue

                if self._config.BASE and vad.Start != self._config.BASE:
                    continue

                # Open the file and initialize the data

                vad_start = self.format_value(vad.Start, "[addrpad]")
                vad_end = self.format_value(vad.End, "[addrpad]")

                path = os.path.join(
                    self._config.DUMP_DIR, "{0}.{1:x}.{2}-{3}.dmp".format(
                    task.ImageFileName, offset, vad_start, vad_end))

                if (task.IsWow64 and vad.u.VadFlags.CommitCharge == 0x7ffffffffffff and 
                        vad.End > 0x7fffffff):
                    result = "Skipping Wow64 MM_MAX_COMMIT range"
                else:
                    result = self.dump_vad(path, vad, task_space)

                self.table_row(outfd, 
                               task.UniqueProcessId, 
                               task.ImageFileName, 
                               vad.Start, vad.End, result)
