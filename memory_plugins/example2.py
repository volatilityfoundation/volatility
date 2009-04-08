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

class memmap_ex_2(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = {} 
    meta_info['author'] = 'AAron Walters'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 AAron Walters'
    meta_info['contact'] = 'awalters@volatilesystems.com'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'https://www.volatilesystems.com/default/volatility'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    # This module extends the standard parser. This is accomplished by 
    # overriding the forensics.commands.command.parser() method. The 
    # overriding method begins by calling the base class method directly
    # then it further populates the OptionParser instance with two 
    # new options.  

    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-o', '--offset',
            help='EPROCESS Offset (in hex)',
            action='store', type='string', dest='offset')

        self.op.add_option('-p', '--pid',
            help='Dump the address space for this Pid',
            action='store', type='int', dest='pid')

    # We need to override the forensics.commands.command.help() method to
    # change the user help message.  This function returns a string that 
    # will be displayed when a user lists available plugins.
   
    def help(self):
        return  "Print the memory map"
    
    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):

        op = self.op
        opts = self.opts

        if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
            op.error("File is required")
        else:
            filename = opts.filename  

        (addr_space, symtab, types) = load_and_identify_image(op, opts)

        if not opts.offset is None:
 
            try:
                offset = int(opts.offset, 16)
            except:
                op.error("EPROCESS offset must be a hexidecimal number.")
 
            try:
                flat_address_space = FileAddressSpace(filename)
            except:
                op.error("Unable to open image file %s" %(filename))

            directory_table_base = process_dtb(flat_address_space, types, offset)

            process_address_space = create_addr_space(addr_space, directory_table_base)

            image_file_name = process_imagename(flat_address_space, types, offset)
            process_id = process_pid(flat_address_space, types, offset)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                return

            addr_space = process_address_space

        else:

            if opts.pid == None:
                op.error("Please specify pid or offset: memmap -p <PID> -o <offset>")
        
            all_tasks = process_list(addr_space, types, symtab)

            task = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
    
            if len(task) == 0:
                print "Error process [%d] not found"%opts.pid
                return

            if len(task) > 1:
                print "Multiple processes [%d] found. Please specify offset."%opts.pid 
                return

            directory_table_base = process_dtb(addr_space, types, task[0])
   
            process_id = process_pid(addr_space, types, task[0])

            process_address_space = create_addr_space(addr_space, directory_table_base)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                return
        
            addr_space = process_address_space


        entries = addr_space.get_available_pages()
  
        print "%-12s %-12s %-12s"%('Virtual','Physical','Size')

        for entry in entries:
            phy_addr = addr_space.vtop(entry[0])
            print "0x%-10x 0x%-10x 0x%-12x"%(entry[0],phy_addr,entry[1])
    


class usrdmp_ex_2(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = {} 
    meta_info['author'] = 'AAron Walters'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 AAron Walters'
    meta_info['contact'] = 'awalters@volatilesystems.com'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'https://www.volatilesystems.com/default/volatility'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    # This module extends the standard parser. This is accomplished by 
    # overriding the forensics.commands.command.parser() method. The 
    # overriding method begins by calling the base class method directly
    # then it further populates the OptionParser instance with two 
    # new options.  
    
    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-o', '--offset',
            help='EPROCESS Offset (in hex)',
            action='store', type='string', dest='offset')

        self.op.add_option('-p', '--pid',
            help='Dump the address space for this Pid',
            action='store', type='int', dest='pid')

    # We need to override the forensics.commands.command.help() method to
    # change the user help message.  This function returns a string that 
    # will be displayed when a user lists available plugins.

    def help(self):
        return  "Dump the address space for a process"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):

        if (self.opts.filename is None) or (not os.path.isfile(self.opts.filename)) :
            self.op.error("File is required")
        else:
            filename = self.opts.filename  

        (addr_space, symtab, types) = load_and_identify_image(self.op, self.opts)

        if not self.opts.offset is None:
 
            try:
                offset = int(self.opts.offset, 16)
            except:
                self.op.error("EPROCESS offset must be a hexidecimal number.")
 
            try:
                flat_address_space = FileAddressSpace(filename)
            except:
                self.op.error("Unable to open image file %s" %(filename))

            directory_table_base = process_dtb(flat_address_space, types, offset)

            process_address_space = create_addr_space(addr_space, directory_table_base)

            image_file_name = process_imagename(flat_address_space, types, offset)
            process_id = process_pid(flat_address_space, types, offset)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                return

            entries = process_address_space.get_available_pages()

            ofilename = opts.offset + ".dmp"

            # Check to make sure file can open
            ohandle=open(ofilename,'wb')

            for entry in entries:
                data = process_address_space.read(entry[0],entry[1])
                ohandle.write("%s"%data)

            ohandle.close()

        else:

            if self.opts.pid == None:
                self.op.error("Please specify pid or offset: usrdmp -p <PID> -o <offset>")

            all_tasks = process_list(addr_space, types, symtab)

            task = process_find_pid(addr_space,types, symtab, all_tasks, self.opts.pid)
    
            if len(task) == 0:
                print "Error process [%d] not found"%self.opts.pid
                return

            if len(task) > 1:
                print "Multiple processes [%d] found. Please specify offset."%self.opts.pid 
                return

            directory_table_base = process_dtb(addr_space, types, task[0])
   
            process_id = process_pid(addr_space, types, task[0])

            process_address_space = create_addr_space(addr_space, directory_table_base)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                return

            image_file_name = process_imagename(process_address_space, types, task[0])

            entries = process_address_space.get_available_pages()

            ofilename = str(self.opts.pid) + ".dmp"

            # Check to make sure file can open
            try:
                ohandle=open(ofilename,'wb')
            except IOError:
                print "Error opening file [%s]"% (ofilename)
                return

            for entry in entries:
                data = process_address_space.read(entry[0],entry[1])
                ohandle.write("%s"%data)

            ohandle.close() 
