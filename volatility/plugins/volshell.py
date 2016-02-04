# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

import struct
import sys
import volatility.plugins.common as common 
import volatility.win32 as win32
import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.taskmods as taskmods
import volatility.scan as scan

try:
    import distorm3 #pylint: disable-msg=F0401
except ImportError:
    pass

class volshell(common.AbstractWindowsCommand):
    """Shell in the memory image"""

    # Declare meta information associated with this plugin

    meta_info = {}
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.3'

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = 'EPROCESS Offset (in hex) in kernel address space',
                          action = 'store', type = 'int')
        config.add_option('IMNAME', short_option = 'n', default = None,
                          help = 'Operate on this Process name',
                          action = 'store', type = 'str')
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')

        self._addrspace = None
        self._proc = None

    def getpidlist(self):
        return win32.tasks.pslist(self._addrspace)

    def getmodules(self):
        return win32.modules.lsmod(self._addrspace)

    def context_display(self):
        print "Current context: {0} @ {1:#x}, pid={2}, ppid={3} DTB={4:#x}".format(self._proc.ImageFileName,
                                                                                  self._proc.obj_offset,
                                                                                  self._proc.UniqueProcessId.v(),
                                                                                  self._proc.InheritedFromUniqueProcessId.v(),
                                                                                  self._proc.Pcb.DirectoryTableBase.v())

    def ps(self, procs = None):
        print "{0:16} {1:6} {2:6} {3:8}".format("Name", "PID", "PPID", "Offset")
        for eproc in procs or self.getpidlist():
            print "{0:16} {1:<6} {2:<6} {3:#08x}".format(eproc.ImageFileName,
                                                       eproc.UniqueProcessId.v(),
                                                       eproc.InheritedFromUniqueProcessId.v(),
                                                       eproc.obj_offset)

    def modules(self, modules = None):
        if self._addrspace.profile.metadata.get('memory_model', '32bit') == '32bit':
            print "{0:10} {1:10} {2}".format("Offset", "Base", "Name")
        else:
            print "{0:18} {1:18} {2}".format("Offset", "Base", "Name")
        for module in modules or self.getmodules():
            print "{0:#08x} {1:#08x} {2}".format(module.obj_offset, 
                                                 module.DllBase,
                                                 module.FullDllName or module.BaseDllName or '')

    def set_context(self, offset = None, pid = None, name = None, physical = False):
        if physical and offset != None:
            offset = taskmods.DllList.virtual_process_from_physical_offset(self._addrspace, offset).obj_offset
        elif pid is not None:
            offsets = []
            for p in self.getpidlist():
                if p.UniqueProcessId.v() == pid:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching pid {0}".format(pid)
                return
            elif len(offsets) > 1:
                print "Multiple processes match {0}, please specify by offset".format(pid)
                print "Matching processes:"
                self.ps(offsets)
                return
            else:
                offset = offsets[0].v()
        elif name is not None:
            offsets = []
            for p in self.getpidlist():
                if p.ImageFileName.find(name) >= 0:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching name {0}".format(name)
                return
            elif len(offsets) > 1:
                print "Multiple processes match name {0}, please specify by PID or offset".format(name)
                print "Matching processes:"
                self.ps(offsets)
                return
            else:
                offset = offsets[0].v()
        elif offset is None:
            print "Must provide one of: offset, name, or pid as a argument."
            return

        self._proc = obj.Object("_EPROCESS", offset = offset, vm = self._addrspace)

        self.context_display()

    def render_text(self, _outfd, _data):
        self._addrspace = utils.load_as(self._config)

        if not self._config.OFFSET is None:
            self.set_context(offset = self._config.OFFSET)

            self.context_display()

        elif self._config.PID is not None:
            # FIXME: volshell is really not intended to switch into multiple
            # process contexts at once, so it doesn't make sense to use a csv
            # pid list. However, the linux and mac volshell call the respective
            # linux_pslist and mac_pslist which require a csv pidlist. After 
            # the 2.3 release we should close this along with issue 375. 
            pidlist = [int(p) for p in self._config.PID.split(',')]
            for p in pidlist:
                self.set_context(pid = p)
                break
        elif self._config.IMNAME is not None:
            self.set_context(name = self._config.IMNAME)
        else:
            # Just use the first process, whatever it is
            for p in self.getpidlist():
                self.set_context(offset = p.v())
                break

        # Functions inside the shell
        def cc(offset = None, pid = None, name = None, physical = False):
            """Change current shell context.

            This function changes the current shell context to to the process
            specified. The process specification can be given as a virtual address
            (option: offset), PID (option: pid), or process name (option: name).

            If multiple processes match the given PID or name, you will be shown a
            list of matching processes, and will have to specify by offset.
            """
            self.set_context(offset = offset, pid = pid, name = name, physical = physical)

        def db(address, length = 0x80, space = None):
            """Print bytes as canonical hexdump.
            
            This function prints bytes at the given virtual address as a canonical
            hexdump. The address will be translated in the current process context
            (see help on cc for information on how to change contexts).
            
            The length parameter (default: 0x80) specifies how many bytes to print,
            the width parameter (default: 16) allows you to change how many bytes per
            line should be displayed, and the space parameter allows you to
            optionally specify the address space to read the data from.
            """
            if not space:
                space = self._proc.get_process_address_space()
            #if length % 4 != 0:
            #    length = (length+4) - (length%4)
            data = space.read(address, length)
            if not data:
                print "Memory unreadable at {0:08x}".format(address)
                return

            for offset, hexchars, chars in utils.Hexdump(data):
                print "{0:#010x}  {1:<48}  {2}".format(address + offset, hexchars, ''.join(chars))

        def dd(address, length = 0x80, space = None):
            """Print dwords at address.

            This function prints the data at the given address, interpreted as
            a series of dwords (unsigned four-byte integers) in hexadecimal.
            The address will be translated in the current process context
            (see help on cc for information on how to change contexts).
            
            The optional length parameter (default: 0x80) controls how many bytes
            to display, and space allows you to optionally specify the address space
            to read the data from.
            """
            if not space:
                space = self._proc.get_process_address_space()
            # round up to multiple of 4
            if length % 4 != 0:
                length = (length + 4) - (length % 4)
            data = space.read(address, length)
            if not data:
                print "Memory unreadable at {0:08x}".format(address)
                return
            dwords = []
            for i in range(0, length, 4):
                (dw,) = struct.unpack("<L", data[i:i + 4])
                dwords.append(dw)

            if len(dwords) % 4 == 0: lines = len(dwords) / 4
            else: lines = len(dwords) / 4 + 1

            for i in range(lines):
                ad = address + i * 0x10
                lwords = dwords[i * 4:i * 4 + 4]
                print ("{0:08x}  ".format(ad)) + " ".join("{0:08x}".format(l) for l in lwords)

        def dq(address, length = 0x80, space = None):
            """Print qwords at address.

            This function prints the data at the given address, interpreted as
            a series of qwords (unsigned eight-byte integers) in hexadecimal.
            The address will be translated in the current process context
            (see help on cc for information on how to change contexts).
            
            The optional length parameter (default: 0x80) controls how many bytes
            to display, and space allows you to optionally specify the address space
            to read the data from.
            """
            if not space:
                space = self._proc.get_process_address_space()

            # round up 
            if length % 8 != 0:
                length = (length + 8) - (length % 8)

            qwords = obj.Object("Array", targetType = "unsigned long long",
                offset = address, count = length / 8, vm = space)

            if not qwords:
                print "Memory unreadable at {0:08x}".format(address)
                return

            for qword in qwords:
                print "{0:#x} {1:#x}".format(qword.obj_offset, qword.v())

        def ps():
            """Print active processes in a table view.

            Prints a process listing with PID, PPID, image name, and offset.
            """
            self.ps()

        def addrspace():
            """Get the current kernel/virtual address space. 

            This returns the current address space. 
            """
            return self._addrspace

        def proc():
            """Get the current process object.
            
            This returns the current process object. 
            """
            return self._proc 

        def getprocs():
            """Generator of process objects (scripting).

            This returns a list of active process objects.
            """    
            return self.getpidlist()

        def getmods():
            """Generator for kernel modules (scripting).

            This returns a list of loaded kernel module objects.
            """
            return self.getmodules()

        def modules():
            """Print loaded modules in a table view.

            Prints a module listing with base, offset, name etc
            """
            self.modules()

        def sc():
            """Show the current context.
            
            Show the current process information.
            """
            self.context_display()

        def list_entry(head, objname, offset = -1, fieldname = None, forward = True, space = None):
            """Traverse a _LIST_ENTRY.

            Traverses a _LIST_ENTRY starting at virtual address head made up of
            objects of type objname. The value of offset should be set to the
            offset of the _LIST_ENTRY within the desired object."""

            vm = space
            if space == None:
                vm = self._proc.get_process_address_space()
            seen = set()

            if fieldname:
                offset = vm.profile.get_obj_offset(objname, fieldname)
                #if typ != "_LIST_ENTRY":
                #    print ("WARN: given field is not a LIST_ENTRY, attempting to "
                #           "continue anyway.")

            lst = obj.Object("_LIST_ENTRY", head, vm)
            seen.add(lst)
            if not lst.is_valid():
                return
            while True:
                if forward:
                    lst = lst.Flink
                else:
                    lst = lst.Blink

                if not lst.is_valid():
                    return

                if lst in seen:
                    break
                else:
                    seen.add(lst)

                nobj = obj.Object(objname, lst.obj_offset - offset, vm)
                yield nobj

        def dt(objct, address = None, space = None, recursive = False, depth = 0):
            """Describe an object or show type info.

            Show the names and values of a complex object (struct). If the name of a
            structure is passed, show the struct's members and their types.

            You can also pass a type name and an address in order to on-the-fly
            interpret a given address as an instance of a particular structure.

            Examples:
                # Dump the current process object
                dt(self._proc)
                # Show the _EPROCESS structure
                dt('_EPROCESS')
                # Overlay an _EPROCESS structure at 0x81234567
                dt('_EPROCESS', 0x81234567)
            """

            profile = (space or self._proc.obj_vm).profile

            if address is not None:
                objct = obj.Object(objct, address, space or self._proc.get_process_address_space())

            try:
                if isinstance(objct, str):
                        size = profile.get_obj_size(objct)
                        membs = [ (profile.get_obj_offset(objct, m), m, profile.vtypes[objct][1][m][1]) for m in profile.vtypes[objct][1] ]
                        print "{0}".format("..." * depth), repr(objct), "({0} bytes)".format(size)
                        for o, m, t in sorted(membs):
                            print "{0}{1:6}: {2:30} {3}".format("..." * depth, hex(o), m, t)
                            if recursive: 
                                if t[0] in profile.vtypes:
                                    dt(t[0], recursive = recursive, depth = depth + 1)
                elif isinstance(objct, obj.BaseObject):
                    membs = [ (o, m) for m, (o, _c) in objct.members.items() ]
                    if not recursive:
                        print repr(objct)
                    offsets = []
                    for o, m in sorted(membs):
                        val = getattr(objct, m)
                        if isinstance(val, list):
                            val = [ str(v) for v in val ]

                        # Handle a potentially callable offset
                        if callable(o):
                            o = o(objct) - objct.obj_offset

                        offsets.append((o, m, val))

                    # Deal with potentially out of order offsets
                    offsets.sort(key = lambda x: x[0])

                    for o, m, val in offsets:
                        try:
                            print "{0}{1:6}: {2:30} {3}".format("..." * depth, hex(o), m, val)
                        except UnicodeDecodeError:
                            print "{0}{1:6}: {2:30} -".format("..." * depth, hex(o), m)
                        if recursive:
                            if val.obj_type in profile.vtypes:
                                dt(val, recursive = recursive, depth = depth + 1)
                elif isinstance(objct, obj.NoneObject):
                    print "ERROR: could not instantiate object"
                    print
                    print "Reason: ", objct.reason
                else:
                    print "ERROR: first argument not an object or known type"
                    print
                    print "Usage:"
                    print
                    hh(dt)
            except TypeError:
                print "Error: could not instantiate object"
                print
                print "Reason: ", "displaying types with dynamic attributes is currently not supported"

        def dis(address, length = 128, space = None, mode = None):
            """Disassemble code at a given address.

            Disassembles code starting at address for a number of bytes
            given by the length parameter (default: 128).

            Note: This feature requires distorm, available at
                http://www.ragestorm.net/distorm/

            The mode is '16bit', '32bit' or '64bit'. If not supplied, the disasm
            mode is taken from the profile. 
            """
            if not sys.modules.has_key("distorm3"):
                print "ERROR: Disassembly unavailable, distorm not found"
                return
            if not space:
                space = self._proc.get_process_address_space()

            if mode == None:
                mode = space.profile.metadata.get('memory_model', '32bit')
            # we'll actually allow the possiblility that someone passed a correct mode
            if mode not in [distorm3.Decode16Bits, distorm3.Decode32Bits, distorm3.Decode64Bits]:
                if mode == '16bit':
                    mode = distorm3.Decode16Bits
                elif mode == '32bit':
                    mode = distorm3.Decode32Bits
                else:
                    mode = distorm3.Decode64Bits
            distorm_mode = mode

            data = space.read(address, length)
            iterable = distorm3.DecodeGenerator(address, data, distorm_mode)
            for (offset, _size, instruction, hexdump) in iterable:
                print "{0:<#8x} {1:<32} {2}".format(offset, hexdump, instruction)

        def find(needle, max = 1, shift = 0, skip = 0, count = False, length = 0x80):
            """Find bytes in the current process's memory
            needle - string or list/tuple of strings to find
            max    - number of results to return; 0 means find all
            shift  - when outputting bytes, start output this many bytes before/after hit offset
            skip   - ignore this many hits
            count  - if True, displays a message reporting how many hits found; only really useful for max == 0
            length - output this many bytes for each hit
            """
            
            if isinstance(needle, basestring):
                needle = [ needle ]
            elif not isinstance(needle, (list, tuple)) or not all([isinstance(x, basestring) for x in needle]):
                print 'Error: needle must be a string or a list/tuple of strings'
                return

            hit_count = 0
            for hit in self._proc.search_process_memory(needle):
                hit_count += 1
                if hit_count > skip:
                    db(hit + shift, length=length)
                    if hit_count - skip == max:
                        break
                    print '-' * 16
            if count:
                print '-' * 16
                print 'Found {} matches.'.format(hit_count - skip)

        shell_funcs = {'find': find, 'cc': cc, 'dd': dd, 'db': db, 'ps': ps, 'dt': dt, 'list_entry': list_entry, 'dis': dis, 'dq': dq, 'modules': modules, 'sc': sc, 'addrspace': addrspace, 'proc': proc, 'getprocs': getprocs, 'getmods': getmods}
        def hh(cmd = None):
            """Get help on a command."""
            shell_funcs['hh'] = hh
            import pydoc
            from inspect import getargspec, formatargspec
            if not cmd:
                print "\nUse addrspace() for Kernel/Virtual AS"
                print "Use addrspace().base for Physical AS"
                print "Use proc() to get the current process object"
                print "  and proc().get_process_address_space() for the current process AS"
                print "  and proc().get_load_modules() for the current process DLLs\n"
                for f in sorted(shell_funcs):
                    doc = pydoc.getdoc(shell_funcs[f])
                    synop, _full = pydoc.splitdoc(doc)
                    print "{0:40} : {1}".format(f + formatargspec(*getargspec(shell_funcs[f])), synop)
                print "\nFor help on a specific command, type 'hh(<command>)'"
            elif type(cmd) == str:
                try:
                    doc = pydoc.getdoc(shell_funcs[cmd])
                except KeyError:
                    print "No such command: {0}".format(cmd)
                    return
                print doc
            else:
                doc = pydoc.getdoc(cmd)
                print doc

        # Break into shell
        banner = "Welcome to volshell! Current memory image is:\n{0}\n".format(self._config.LOCATION)
        banner += "To get help, type 'hh()'"
        try:
            import IPython
            try:
                # New versions of IPython
                IPython.embed()
            except AttributeError:
                # Old versions of IPythom
                shell = IPython.Shell.IPShellEmbed([], banner = banner)
                shell()
        except (AttributeError, ImportError):
            import code, inspect

            frame = inspect.currentframe()

            # Try to enable tab completion
            try:
                import rlcompleter, readline #pylint: disable-msg=W0612
                readline.parse_and_bind("tab: complete")
            except ImportError:
                pass

            # evaluate commands in current namespace
            namespace = frame.f_globals.copy()
            namespace.update(frame.f_locals)

            code.interact(banner = banner, local = namespace)
