# Volatility
# 
# Based on the source code from
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
#
# Authors:
# Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
# The source code in this file was inspired by the excellent work of
# Brendan Dolan-Gavitt. Background information can be found in 
# the following reference:
# "The VAD Tree: A Process-Eye View of Physical Memory," Brendan Dolan-Gavitt

import os.path
import volatility.plugins.taskmods as taskmods
import volatility.debug as debug #pylint: disable-msg=W0611

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
            for vad in task.get_vads():
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
        outfd.write("VAD node @{0:08x} Start {1:08x} End {2:08x} Tag {3:4}\n".format(
            vad.obj_offset, vad.get_start(), vad.get_end(), vad.Tag))
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

        control_area = vad.get_control_area()
        if not control_area:
            #debug.b()
            return

        outfd.write("ControlArea @{0:08x} Segment {1:08x}\n".format(control_area.dereference().obj_offset, control_area.Segment))
        outfd.write("Dereference list: Flink {0:08x}, Blink {1:08x}\n".format(control_area.DereferenceList.Flink, control_area.DereferenceList.Blink))
        outfd.write("NumberOfSectionReferences: {0:10} NumberOfPfnReferences:  {1:10}\n".format(control_area.NumberOfSectionReferences, control_area.NumberOfPfnReferences))
        outfd.write("NumberOfMappedViews:       {0:10} NumberOfUserReferences: {1:10}\n".format(control_area.NumberOfMappedViews, control_area.NumberOfUserReferences))
        outfd.write("WaitingForDeletion Event:  {0:08x}\n".format(control_area.WaitingForDeletion))
        outfd.write("Control Flags: {0}\n".format(str(control_area.u.Flags)))

        file_object = vad.get_file_object()

        if file_object:
            outfd.write("FileObject @{0:08x} FileBuffer @ {1:08x}          , Name: {2}\n".format(file_object.obj_offset, file_object.FileName.Buffer, file_object.FileName))

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
            for vad in task.get_vads():
                if vad:
                    level = levels.get(vad.get_parent().dereference().obj_offset, -1) + 1
                    levels[vad.obj_offset] = level
                    outfd.write(" " * level + "{0:08x} - {1:08x}\n".format(
                                vad.get_start(),
                                vad.get_end()))

    def render_dot(self, outfd, data):
        for task in data:
            outfd.write("/" + "*" * 72 + "/\n")
            outfd.write("/* Pid: {0:6} */\n".format(task.UniqueProcessId))
            outfd.write("digraph processtree {\n")
            outfd.write("graph [rankdir = \"TB\"];\n")
            for vad in task.get_vads():
                if vad:
                    if vad.get_parent() and vad.get_parent().dereference():
                        outfd.write("vad_{0:08x} -> vad_{1:08x}\n".format(vad.get_parent().dereference().obj_offset or 0, vad.obj_offset))
                    outfd.write("vad_{0:08x} [label = \"{{ {1}\\n{2:08x} - {3:08x} }}\""
                                "shape = \"record\" color = \"blue\"];\n".format(
                        vad.obj_offset,
                        vad.Tag,
                        vad.get_start(),
                        vad.get_end()))

            outfd.write("}\n")

class VADWalk(VADInfo):
    """Walk the VAD tree"""

    def render_text(self, outfd, data):
        for task in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            outfd.write("Address  Parent   Left     Right    Start    End      Tag\n")
            for vad in task.get_vads():
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad:
                    outfd.write("{0:08x} {1:08x} {2:08x} {3:08x} {4:08x} {5:08x} {6:4}\n".format(
                        vad.obj_offset,
                        vad.get_parent().dereference().obj_offset or 0,
                        vad.LeftChild.dereference().obj_offset or 0,
                        vad.RightChild.dereference().obj_offset or 0,
                        vad.get_start(),
                        vad.get_end(),
                        vad.Tag))

class VADDump(VADInfo):
    """Dumps out the vad sections to a file"""

    def __init__(self, config, *args, **kwargs):
        VADInfo.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump the VAD files')

        config.add_option('VERBOSE', short_option = 'v', default = False, type = 'bool',
                          cache_invalidator = False,
                          help = 'Print verbose progress information')

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for task in data:
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            # Get the task and all process specific information
            task_space = task.get_process_address_space()
            name = task.ImageFileName
            offset = task_space.vtop(task.obj_offset)

            outfd.write("*" * 72 + "\n")
            for vad in task.get_vads():
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad == None:
                    continue

                # Find the start and end range
                start = vad.get_start()
                end = vad.get_end()

                # Open the file and initialize the data
                f = open(os.path.join(self._config.DUMP_DIR, "{0}.{1:x}.{2:08x}-{3:08x}.dmp".format(name, offset, start, end)), 'wb')
                range_data = vad.get_data()

                if self._config.VERBOSE:
                    outfd.write("Writing VAD for " + ("{0}.{1:x}.{2:08x}-{3:08x}.dmp".format(name, offset, start, end)) + "\n")
                f.write(range_data)
                f.close()
