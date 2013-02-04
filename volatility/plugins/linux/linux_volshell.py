# Volatility
# Copyright (C) 2008 Volatile Systems
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

import sys, struct
import volatility.plugins.linux.common as common 
import volatility.plugins.linux.pslist as pslist
import volatility.obj as obj
import volatility.utils as utils

try:
    import distorm3 #pylint: disable-msg=F0401
except ImportError:
    pass

### FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME
### a majority of this plugin can be shared with the windows 
### volshell command, but not until the windows volshell is 
### refactored to be more inheritance-friendly. in the 
### meantime, we accept code duplication in favor of being 
### able to explore linux images interactively. 

class linux_volshell(common.AbstractLinuxCommand):
    """Shell in the memory image"""
    
    def __init__(self, config, *args, **kwargs):
        common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
            
        # pre-populate the process list
        self.tasks = list(pslist.linux_pslist(self._config).calculate())

        # the initial task is init 
        self.task = self.tasks[0]

    def ps(self):
        print "{0:16} {1:6} {2:8}".format("Name", "PID", "Offset")
        for task in self.tasks:
            print "{0:16} {1:<6} {2:#08x}".format(task.comm, task.pid, task.obj_offset)

    def context_display(self):
        dtb = self.addr_space.vtop(self.task.mm.pgd) or self.task.mm.pgd
        print "Current context: process {0}, pid={1} DTB={2:#x}".format(self.task.comm,
                                                                        self.task.pid, dtb)

    def set_context(self, offset = None, pid = None):
    
        if pid is None and offset is None:
            print "Must provide offset or pid as an argument."
            return
    
        if pid is not None:
            tasks = []
            for task in self.tasks:
                if task.pid == pid:
                    tasks.append(task)
            if not tasks:
                print "Unable to find process matching pid {0}".format(pid)
                return
            elif len(tasks) > 1:
                print "Multiple processes match {0}, please specify by offset".format(pid)
                return
            else:
                task = tasks[0]
        else:
            task = obj.Object("task_struct", offset = offset, vm = self.addr_space)
            
        self.task = task
        self.context_display()

    def render_text(self, _outfd, _data):
    
        common.set_plugin_members(self)
        
        ## display the initial context set to 'init' process
        self.context_display()

        def cc(offset = None, pid = None):
            """Change current shell context"""
            self.set_context(offset = offset, pid = pid)

        def ps():
            """Print a process listing"""
            self.ps()

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
                space = self.task.get_process_address_space()
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
                space = self.task.get_process_address_space()
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
                space = self.task.get_process_address_space()

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

        def dt(objct, address = None, address_space = None):

            profile = (address_space or self.addr_space).profile

            if address is not None:
                objct = obj.Object(objct, address, address_space or self.task.get_process_address_space())

            if isinstance(objct, str):
                size = profile.get_obj_size(objct)
                membs = [ (profile.get_obj_offset(objct, m), m, profile.vtypes[objct][1][m][1]) for m in profile.vtypes[objct][1] ]
                print repr(objct), "({0} bytes)".format(size)
                for o, m, t in sorted(membs):
                    print "{0:6}: {1:30} {2}".format(hex(o), m, t)
            elif isinstance(objct, obj.BaseObject):
                membs = [ (o, m) for m, (o, _c) in objct.members.items() ]
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
                    print "{0:6}: {1:30} {2}".format(hex(o), m, val)
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

        def dis(address, length = 128, space = None, mode = None):
            """Disassemble code at a given address.

            Disassembles code starting at address for a number of bytes
            given by the length parameter (default: 128).

            Note: This feature requires distorm, available at
                http://www.ragestorm.net/distorm/

            The mode is '32bit' or '64bit'. If not supplied, the disasm
            mode is taken from the profile. 
            """
            if not sys.modules.has_key("distorm3"):
                print "ERROR: Disassembly unavailable, distorm not found"
                return
            if not space:
                space = self.task.get_process_address_space()

            if not mode:
                mode = space.profile.metadata.get('memory_model', '32bit')

            if mode == '32bit':
                distorm_mode = distorm3.Decode32Bits
            else:
                distorm_mode = distorm3.Decode64Bits

            data = space.read(address, length)
            iterable = distorm3.DecodeGenerator(address, data, distorm_mode)
            for (offset, _size, instruction, hexdump) in iterable:
                print "{0:<#8x} {1:<32} {2}".format(offset, hexdump, instruction)

        shell_funcs = {'dt': dt, 'cc': cc, 'db': db, 'dd': dd, 'dq': dq, 'dis': dis}
        def hh(cmd = None):
            """Get help on a command."""
            shell_funcs['hh'] = hh
            import pydoc
            from inspect import getargspec, formatargspec
            if not cmd:
                for f in shell_funcs:
                    doc = pydoc.getdoc(shell_funcs[f])
                    synop, _full = pydoc.splitdoc(doc)
                    print "{0:40} : {1}".format(f + formatargspec(*getargspec(shell_funcs[f])), synop)
                print
                print "For help on a specific command, type 'hh(<command>)'"
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
            from IPython.Shell import IPShellEmbed #pylint: disable-msg=W0611,F0401
            shell = IPShellEmbed([], banner = banner)
            shell()
        except ImportError:
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
