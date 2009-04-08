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

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

from forensics.object2 import *
from forensics.object import *
from vutils import *
from forensics.win32.tasks import *

class pslist_ex_3(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = {} 
    meta_info['author'] = 'AAron Walters'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 AAron Walters'
    meta_info['contact'] = 'awalters@volatilesystems.com'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'https://www.volatilesystems.com/default/volatility'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'
        
    # This module makes use of the standard parser. Thus it is not 
    # necessary to override the forensics.commands.command.parser() method.
    # The standard parser provides the following command line options:
    #    '-f', '--file', '(required) Image file'
    #    '-b', '--base', '(optional) Physical offset (in hex) of DTB'
    #    '-t', '--type', '(optional) Identify the image type'


    # We need to override the forensics.commands.command.help() method to
    # change the user help message.  This function returns a string that 
    # will be displayed when a user lists available plugins.

    def help(self):
        return  "Print list running processes"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):

        theProfile = Profile()

        (addr_space, symtab, types) = load_and_identify_image(self.op, \
            self.opts)

        all_tasks = process_list(addr_space,types,symtab)

        print "%-20s %-6s %-6s %-6s %-6s %-6s"% \
            ('Name','Pid','PPid','Thds','Hnds','Time')

        for task in all_tasks:
            if not addr_space.is_valid_address(task):
                continue

            eprocess = Object('_EPROCESS', task, addr_space, None, theProfile, ['example3'])
            image_file_name = eprocess.ImageFileName
            process_id = eprocess.UniqueProcessId.v()
            active_threads = eprocess.ActiveThreads
            inherited_from = eprocess.InheritedFromUniqueProcessId.v()

            if eprocess.ObjectTable and eprocess.ObjectTable.is_valid():
                handle_count = eprocess.ObjectTable.HandleCount
            else:
                handle_count = None

            create_time = eprocess.CreateTime
 
            if not create_time is None:
                create_time=strftime("%a %b %d %H:%M:%S %Y",\
                    gmtime(create_time))     

            defaults = {0:"UNKNOWN",1:-1,2:-1,3:-1,4:-1,5:"UNKNOWN"}

            PrintWithDefaults("%-20s %-6d %-6d %-6d %-6d %-26s", \
                                                   (image_file_name,
                                                   process_id,
                                                   inherited_from,
                                                   active_threads,
                                                   handle_count,
                                                   create_time),defaults)

class _EPROCESS(Object):
    """Class representing an _EPROCESS.

    Adds the following special behavior:
      * Uses self.Pcb.DirectoryTableBase to re-calculate its
        address space.
      * Presents ImageFileName as a Python string rather than
        an array of unsigned chars.
    """
    hasMembers = True
    name = "_EPROCESS"

    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj
    
    def __init__(self, name, address, space, parent=None, profile=None, \
                 objdefs=None):
        super(_EPROCESS,self).__init__(name, address, space, parent, profile, \
	         objdefs)
        new_dtb = self.Pcb.DirectoryTableBase[0]
        self.vm = create_addr_space(self.vm, new_dtb)
    
    # Custom attributes
    def getImageFileName(self):
        return read_null_string(self.vm, types,
                ['_EPROCESS', 'ImageFileName'], self.offset)
    ImageFileName = property(fget=getImageFileName)

    def getCreateTime(self):
        return process_create_time(self.vm, types, self.offset)
    CreateTime = property(fget=getCreateTime)
