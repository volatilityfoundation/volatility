#!c:\python\python.exe
#  -*- mode: python; -*-
#
# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

import sys
import os
import forensics.registry as MemoryRegistry

from vmodules import *

modules = {
    'datetime':
    VolatoolsModule('datetime',
                    'Get date/time information for image',
                    get_datetime),
    'pslist':
    VolatoolsModule('pslist',
                    'Print list of running processes',
                    get_pslist),
    'dlllist':
    VolatoolsModule('dlllist',
                    'Print list of loaded dlls for each process',
                    get_dlllist),
    'sockets':
    VolatoolsModule('sockets',
                    'Print list of open sockets',
                    get_sockets),
    'files':
    VolatoolsModule('files',
                    'Print list of open files for each process',
                    get_open_files),
    'connections':
    VolatoolsModule('connections',
                    'Print list of open connections',
                    get_connections),    
    'modules':
    VolatoolsModule('modules',
                    'Print list of loaded modules',
                    get_modules),
    'strings':
    VolatoolsModule('strings',
                    'Match physical offsets to virtual addresses (may take a while, VERY verbose)',
                    get_strings),
    'ident':
    VolatoolsModule('ident',
                    'Identify image properties',
                    get_image_info),
    'vadinfo':
            VolatoolsModule('vadinfo',
                    'Dump the VAD info',
	             vadinfo),
    'vaddump':
            VolatoolsModule('vaddump',
		    'Dump the Vad sections to files',
		    vaddump),
    'vadwalk':
            VolatoolsModule('vadwalk',
		    'Walk the vad tree',
		    vadwalk),
    'psscan':
            VolatoolsModule('psscan',
		    'Scan for EPROCESS objects',
		    psscan),
    'thrdscan':
            VolatoolsModule('thrdscan',
		    'Scan for ETHREAD objects',
     		    thrdscan),
    'sockscan':
            VolatoolsModule('sockscan',
		    'Scan for socket objects',
		    sockscan),
    'connscan':
            VolatoolsModule('connscan',
		    'Scan for connection objects',
		    connscan),
    'memmap':
            VolatoolsModule('memmap',
		    'Print the memory map',
		    mem_map),
    'modscan':
    VolatoolsModule('modscan',
            'Scan for modules',
            modscan), 
    'dmpchk':
    VolatoolsModule('dmpchk',
            'Dump crash dump information',
            dump_chk), 
    'memdmp':
    VolatoolsModule('memdmp',
            'Dump the addressable memory for a process',
            mem_dump), 
    'raw2dmp':
        VolatoolsModule('raw2dmp',
                    'Convert a raw dump to a crash dump',
                    raw2dmp),
    'dmp2raw':
        VolatoolsModule('dmp2raw',
                    'Convert a crash dump to a raw dump',
                    dmp2raw),
    'regobjkeys':
    VolatoolsModule('regkeys',
                  'Print list of open regkeys for each process',
                  get_open_keys),
    'procdump':
    VolatoolsModule('procdump',
                  'Dump a process to an executable sample',
                  procdump),
    'connscan2':
    VolatoolsModule('connscan2',
                  'Scan for connection objects (New)',
                  connscan2),
    'sockscan2':
    VolatoolsModule('sockscan2',
                  'Scan for socket objects (New)',
                  sockscan2),
    'modscan2':
    VolatoolsModule('modscan2',
                  'Scan for module objects (New)',
                  modscan2),
    'thrdscan2':
    VolatoolsModule('thrdscan2',
                  'Scan for thread objects (New)',
                  thrdscan2),
    'psscan2':
    VolatoolsModule('psscan2',
                  'Scan for process objects (New)',
                  psscan2),
    'hibinfo':
    VolatoolsModule('hibinfo',
            'Convert hibernation file to linear raw image',
            hibinfo), 
    }


def list_modules():
    global modules
    print "\tSupported Internel Commands:"
    keys = modules.keys()
    keys.sort()
    for mod in keys:
        print "\t\t%-15s\t%-s" % (mod, modules[mod].desc())        

def list_plugins():
    print "\tSupported Plugin Commands:"
    keys = MemoryRegistry.PLUGIN_COMMANDS.commands.keys()
    keys.sort()
    for cmdname in keys:
        command=MemoryRegistry.PLUGIN_COMMANDS[cmdname]()
        print "\t\t%-15s\t%-s" % (cmdname, command.help())      


def usage(progname):
    print ""
    print "\tVolatile Systems Volatility Framework v1.3"
    print "\tCopyright (C) 2007,2008 Volatile Systems"
    print "\tCopyright (C) 2007 Komoku, Inc."
    print "\tThis is free software; see the source for copying conditions."
    print "\tThere is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
    print ""
    print "\tusage: %s cmd [cmd_opts]\n" % (progname)
    print "\tRun command cmd with options cmd_opts"
    print "\tFor help on a specific command, run '%s cmd --help'" % (progname)
    print
    list_modules()
    print
    list_plugins()
    print
    print "\tExample: volatility pslist -f /path/to/my/file"
    sys.exit(0)

def main(argv=sys.argv):

    MemoryRegistry.Init()

    if (len(argv) < 2):
        usage(os.path.basename(argv[0]))

    if not modules.has_key(argv[1]) and \
        not MemoryRegistry.PLUGIN_COMMANDS.commands.has_key(argv[1]):
        print "Error: Invalid module [%s]." % (argv[1])
        usage(argv[0])

    if modules.has_key(argv[1]):
        modules[argv[1]].execute(argv[1], argv[2:])
    elif MemoryRegistry.PLUGIN_COMMANDS.commands.has_key(argv[1]):
        command=MemoryRegistry.PLUGIN_COMMANDS[argv[1]](argv[2:])
        command.execute()


if __name__ == "__main__":
    main()

1

