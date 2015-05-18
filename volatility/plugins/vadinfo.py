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
# The source code in this file was inspired by the excellent work of
# Brendan Dolan-Gavitt. Background information can be found in 
# the following reference:
# "The VAD Tree: A Process-Eye View of Physical Memory," Brendan Dolan-Gavitt

import os.path
import volatility.obj as obj
import volatility.plugins.taskmods as taskmods
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.constants as constants
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

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

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option('ADDR', short_option = 'a', default = None,
                          help = 'Show info on VAD at or containing this address',
                          action = 'store', type = 'int')
                          
    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                       ("VADNodeAddress", Address),
                       ("Start", Address),
                       ("End", Address),
                       ("Tag", str),
                       ("Flags", str),
                       ("Protection", str),
                       ("VadType", str),
                       ("ControlArea", Address),
                       ("Segment", Address),
                       ("NumberOfSectionReferences", int),
                       ("NumberOfPfnReferences", int),
                       ("NumberOfMappedViews", int),
                       ("NumberOfUserReferences", int),
                       ("Control Flags", str),
                       ("FileObject", Address),
                       ("FileNameWithDevice", str),
                       ("FirstPrototypePte", Address),
                       ("LastContiguousPte", Address),
                       ("Flags2", str)],
                        self.generator(data))

    def generator(self, data):
        for task in data:
            for vad in task.VadRoot.traverse():
                if (self._config.ADDR is not None and 
                            (self._config.ADDR < vad.Start or 
                            self._config.ADDR > vad.End)):
                    continue
                if vad != None:    
                    #Init vad control and ext variables 
                    controlAreaAddr = 0
                    segmentAddr = 0
                    numberOfSectionReferences = -1
                    numberOfPfnReferences = -1
                    numberOfMappedViews = -1
                    numberOfUserReferences = -1
                    controlFlags = ""
                    fileObjectAddr = 0
                    fileNameWithDevice = ""
                    firstPrototypePteAddr = 0
                    lastContiguousPteAddr = 0
                    flags2 = ""
                    vadType = ""
                    
                    protection = PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), hex(vad.VadFlags.Protection))
                    
                    
                    # translate the vad type if its available (> XP)
                    if hasattr(vad.VadFlags, "VadType"):
                        vadType = MI_VAD_TYPE.get(vad.VadFlags.VadType.v(), hex(vad.VadFlags.VadType))

                    try:
                        control_area = vad.ControlArea
                        # even if the ControlArea is not NULL, it is only meaningful 
                        # for shared (non private) memory sections. 
                        if vad.VadFlags.PrivateMemory != 1 and control_area:                
                            if control_area:        
                                controlAreaAddr = control_area.dereference().obj_offset
                                segmentAddr = control_area.Segment
                                numberOfSectionReferences = control_area.NumberOfSectionReferences
                                numberOfPfnReferences = control_area.NumberOfPfnReferences
                                numberOfMappedViews = control_area.NumberOfMappedViews
                                numberOfUserReferences = control_area.NumberOfUserReferences
                                controlFlags = control_area.u.Flags 
                                file_object = vad.FileObject

                                if file_object:
                                    fileObjectAddr = file_object.obj_offset
                                    fileNameWithDevice = file_object.file_name_with_device()
                    except AttributeError:
                        pass
                    try:
                        firstPrototypePteAddr = vad.FirstPrototypePte
                        lastContiguousPteAddr = vad.LastContiguousPte
                        flags2 = str(vad.u2.VadFlags2)
                    except AttributeError:
                        pass

                    yield(0, [int(task.UniqueProcessId),
                            Address(vad.obj_offset),
                            Address(vad.Start),
                            Address(vad.End),
                            str(vad.Tag or ''),
                            str(vad.VadFlags or ''),
                            str(protection or ''),
                            str(vadType or ''),
                            Address(controlAreaAddr),
                            Address(segmentAddr),
                            int(numberOfSectionReferences),
                            int(numberOfPfnReferences),
                            int(numberOfMappedViews),
                            int(numberOfUserReferences),
                            str(controlFlags or ''),
                            Address(fileObjectAddr),
                            str(fileNameWithDevice or ''),
                            Address(firstPrototypePteAddr),
                            Address(lastContiguousPteAddr),
                            str(flags2 or '')])
                
                
    def render_text(self, outfd, data):
        for task in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            for vad in task.VadRoot.traverse():
                if (self._config.ADDR is not None and 
                            (self._config.ADDR < vad.Start or 
                            self._config.ADDR > vad.End)):
                    continue
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
        outfd.write("Flags: {0}\n".format(str(vad.VadFlags)))
        # although the numeric value of Protection is printed above with VadFlags,
        # let's show the user a human-readable translation of the protection 
        outfd.write("Protection: {0}\n".format(PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), hex(vad.VadFlags.Protection))))
        # translate the vad type if its available (> XP)
        if hasattr(vad.VadFlags, "VadType"):
            outfd.write("Vad Type: {0}\n".format(MI_VAD_TYPE.get(vad.VadFlags.VadType.v(), hex(vad.VadFlags.VadType))))

    def write_vad_control(self, outfd, vad):
        """Renders a text version of a (non-short) Vad's control information"""

        # even if the ControlArea is not NULL, it is only meaningful 
        # for shared (non private) memory sections. 
        if vad.VadFlags.PrivateMemory == 1:
            return

        control_area = vad.ControlArea
        if not control_area:
            return

        outfd.write("ControlArea @{0:08x} Segment {1:08x}\n".format(control_area.dereference().obj_offset, control_area.Segment))
        outfd.write("NumberOfSectionReferences: {0:10} NumberOfPfnReferences:  {1:10}\n".format(control_area.NumberOfSectionReferences, control_area.NumberOfPfnReferences))
        outfd.write("NumberOfMappedViews:       {0:10} NumberOfUserReferences: {1:10}\n".format(control_area.NumberOfMappedViews, control_area.NumberOfUserReferences))
        outfd.write("Control Flags: {0}\n".format(str(control_area.u.Flags)))

        file_object = vad.FileObject

        if file_object:
            outfd.write("FileObject @{0:08x}, Name: {1}\n".format(file_object.obj_offset, str(file_object.file_name_with_device() or '')))

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
            heaps = task.Peb.ProcessHeaps.dereference()
            modules = [mod.DllBase for mod in task.get_load_modules()]
            stacks = []
            for thread in task.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
                teb = obj.Object("_TEB", 
                                 offset = thread.Tcb.Teb,
                                 vm = task.get_process_address_space())
                if teb:
                    stacks.append(teb.NtTib.StackBase)
            for vad in task.VadRoot.traverse():
                if vad:
                    if vad.Parent:
                        outfd.write("vad_{0:08x} -> vad_{1:08x}\n".format(vad.Parent.obj_offset or 0, vad.obj_offset))
                        fillcolor = "white"
                        if vad.Start in heaps:
                            fillcolor = "red"
                        elif vad.Start in modules:
                            fillcolor = "gray"
                        elif vad.Start in stacks:
                            fillcolor = "green"
                        else:
                            try:
                                if vad.FileObject.FileName:
                                    fillcolor = "yellow"
                            except AttributeError:
                                pass                        
                        outfd.write("vad_{0:08x} [label = \"{{ {1}\\n{2:08x} - {3:08x} }}\""
                                "shape = \"record\" color = \"blue\" fillcolor = \"{4}\"];\n".format(
                        vad.obj_offset,
                        vad.Tag,
                        vad.Start,
                        vad.End, 
                        fillcolor))

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
        config.remove_option("ADDR")
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

            # as a first step, we try to get the physical offset of the
            # _EPROCESS object using the process address space
            offset = task_space.vtop(task.obj_offset)
            # if this fails, we'll get its physical offset using kernel space
            if offset == None:
                offset = task.obj_vm.vtop(task.obj_offset)
            # if this fails we'll manually set the offset to 0
            if offset == None:
                offset = 0

            for vad, _addrspace in task.get_vads(skip_max_commit = True):

                if self._config.BASE and vad.Start != self._config.BASE:
                    continue

                # Open the file and initialize the data

                vad_start = self.format_value(vad.Start, "[addrpad]")
                vad_end = self.format_value(vad.End, "[addrpad]")

                path = os.path.join(
                    self._config.DUMP_DIR, "{0}.{1:x}.{2}-{3}.dmp".format(
                    task.ImageFileName, offset, vad_start, vad_end))

                result = self.dump_vad(path, vad, task_space)

                self.table_row(outfd, 
                               task.UniqueProcessId, 
                               task.ImageFileName, 
                               vad.Start, vad.End, result)
