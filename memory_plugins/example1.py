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
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

from vutils import *
from forensics.win32.tasks import *

class pslist_ex_1(forensics.commands.command):

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

        (addr_space, symtab, types) = load_and_identify_image(self.op, self.opts)

        all_tasks = process_list(addr_space,types,symtab)

        print "%-20s %-6s %-6s %-6s %-6s %-6s"%('Name','Pid','PPid','Thds','Hnds','Time')

        for task in all_tasks:
            if not addr_space.is_valid_address(task):
                continue

            image_file_name = process_imagename(addr_space, types, task)
            if image_file_name is None:
                image_file_name = "UNKNOWN"

            process_id      = process_pid(addr_space, types, task)
            if process_id is None:
                process_id = -1

            active_threads  = process_num_active_threads(addr_space, types, task)
            if active_threads is None:
                active_threads = -1

            inherited_from  = process_inherited_from(addr_space, types,task)
            if inherited_from is None:
                inherited_from = -1

            handle_count    = process_handle_count(addr_space, types, task)
            if handle_count is None:
                handle_count = -1

            create_time     = process_create_time(addr_space, types, task)
            if create_time is None:
                create_time = "UNKNOWN"
            else:
                create_time=strftime("%a %b %d %H:%M:%S %Y",gmtime(create_time))     

            print "%-20s %-6d %-6d %-6d %-6d %-26s" % (image_file_name,
                                                   process_id,
                                                   inherited_from,
                                                   active_threads,
                                                   handle_count,
                                                   create_time)
