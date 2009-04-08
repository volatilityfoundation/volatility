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


from vutils import *
from forensics.win32.datetime import *
from forensics.win32.tasks import *
from forensics.win32.network import *
from forensics.win32.handles import *
from forensics.win32.modules import *
from forensics.win32.vad import *
from forensics.win32.scan import *
from forensics.win32.crash_addrspace import *
from forensics.win32.hiber_addrspace import *
from forensics.win32.crashdump import *
import forensics.win32.meta_info as meta_info
from forensics.win32.xpress import xpress_decode
from forensics.win32.registry import print_entry_keys
from forensics.win32.executable import rebuild_exe_dsk,rebuild_exe_mem
from forensics.win32.scan2 import *

class VolatoolsModule:
    def __init__(self, cmd_name, cmd_desc, cmd_execute):
        self.cmd_name = cmd_name
        self.cmd_desc = cmd_desc
        self.cmd_execute = cmd_execute


    def desc(self):
        return self.cmd_desc

    def execute(self, module, args):
        self.cmd_execute(module, args)


###################################
#  identify
###################################
def get_image_info(cmdname, argv):
    """
    Function provides as many characteristics as can be identified for given image.
    """
    op = get_standard_parser(cmdname)
    
    opts, args = op.parse_args(argv)

    if not opts.base is None:
        print "Ignoring option -b"
        opts.base = None

    if not opts.type is None:
        print "Ignoring option -t"
        opts.type = None

    (addr_space, symtab, types) = load_and_identify_image(op, opts, True)

    if not addr_space is None and not symtab is None:
        KUSER_SHARED_DATA = 0xFFDF0000    

        if not addr_space.is_valid_address(KUSER_SHARED_DATA):
            print "%25s UNAVAILABLE" % ("Datetime:")
            return
    
    
        time = windows_to_unix_time(local_time(addr_space, types, KUSER_SHARED_DATA))
        ts = format_time(time)

        print "%25s %s"% ("Datetime:", ts)

###################################
#  Datetime
###################################
def format_time(time):
    ts=strftime("%a %b %d %H:%M:%S %Y",
                gmtime(time))
    return ts
    
def get_datetime(cmdname, argv):
    """
    Function prints a formatted string of the image local time.
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    KUSER_SHARED_DATA = 0xFFDF0000

    if not addr_space.is_valid_address(KUSER_SHARED_DATA):
        print "ERROR: KUSER_SHARED_DATA Invalid: Try a different Page Directory Base"
        return
    
    time = windows_to_unix_time(local_time(addr_space, types, KUSER_SHARED_DATA))
    ts = format_time(time)

    print "Image local date and time: %s"%ts    

###################################
#  modules list
###################################
def get_modules(cmdname, argv):
    """
    Function prints a formatted table of module information
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
    
    all_modules = modules_list(addr_space, types, symtab)

    print "%-50s %-12s %-8s %s" %('File','Base', 'Size', 'Name')

    for module in all_modules:
        if not addr_space.is_valid_address(module):
            continue
        module_image = module_imagename(addr_space, types, module)
        if module_image is None:
            module_image = "UNKNOWN"
            
        module_name = module_modulename(addr_space, types, module)
        if module_name is None:
            module_name = "UNKNOWN"

        module_base = module_baseaddr(addr_space, types, module)
        if module_base is None:
            module_base = "UNKNOWN"
        else:
            module_base = "0x%010x" % module_base

        module_size = module_imagesize(addr_space, types, module)
        
        print "%-50s %s 0x%06x %s" % (module_image, module_base, module_size, module_name)

###################################
#  pslist - process list
###################################
def get_pslist(cmdname, argv):
    """
    Function prints a formatted table of process information for image
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    all_tasks = process_list(addr_space, types, symtab)

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
            create_time = format_time(create_time)            

        print "%-20s %-6d %-6d %-6d %-6d %-26s" % (image_file_name,
                                                   process_id,
                                                   inherited_from,
                                                   active_threads,
                                                   handle_count,
                                                   create_time)

###################################
#  dlllist - DLL list
###################################
def get_dlllist(cmdname, argv):
    """
    Function prints a list of dlls loaded in each process
    """
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
               help='EPROCESS Offset (in hex) in physical address space',
               action='store', type='string', dest='offset')
    op.add_option('-p', '--pid',
                  help='Get info for this Pid',
                  action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)

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

        if process_address_space is None:
            print "Error obtaining address space for process [%d]" % (process_id)
            return


        image_file_name = process_imagename(flat_address_space, types, offset)

        process_id = process_pid(flat_address_space, types, offset)
                            
        print "%s pid: %d"%(image_file_name, process_id)

        peb = process_peb(flat_address_space, types, offset)

        if not process_address_space.is_valid_address(peb):
            print "Unable to read PEB for task."
            return

        command_line = process_command_line(process_address_space, types, peb)

        if command_line is None:
            command_line = "UNKNOWN"

        print "Command line : %s" % (command_line)

        print
        
        modules = process_ldrs(process_address_space, types, peb)

        if len(modules) > 0:
            print "%-12s %-12s %s"%('Base','Size','Path')
        
        for module in modules:
            if not process_address_space.is_valid_address(module):
                return
            path = module_path(process_address_space, types, module)
            if path is None:
                path = "%-10s  " % ('UNKNOWN')
                
            base = module_base(process_address_space, types, module)
            if base is None:
                base = "%-10s  " % ('UNKNOWN')
            else:
                base = "0x%-10x" % (base)
                
            size = module_size(process_address_space, types, module)
            if size is None:
                size = "%-10s  " % ('UNKNOWN')
            else:
                size = "0x%-10x" % (size)
                
            print "%s %s %s"%(base,size,path)            
            
        print

    else:
    
        # get list of windows processes
        all_tasks = process_list(addr_space, types, symtab)        

        if not opts.pid == None:
            all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found"%opts.pid

        star_line = '*'*72
    
        for task in all_tasks:

            if not addr_space.is_valid_address(task):
                continue
            
            if len(all_tasks) > 1:
                print "%s"%star_line
        
            image_file_name = process_imagename(addr_space, types, task)

            process_id = process_pid(addr_space, types, task)

        
            print "%s pid: %d"%(image_file_name, process_id)
        
            process_address_space = process_addr_space(addr_space, types, task, opts.filename)
            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                continue
                            
            peb = process_peb(addr_space, types, task)

            if not process_address_space.is_valid_address(peb):
                print "Unable to read PEB for task."
                continue

            command_line = process_command_line(process_address_space, types, peb)

            if command_line is None:
                command_line = "UNKNOWN"

            print "Command line : %s" % (command_line)
      
            print read_unicode_string(process_address_space, types,
                ['_PEB', 'CSDVersion'], peb)

            print
        
            modules = process_ldrs(process_address_space, types, peb)

            if len(modules) > 0:
                print "%-12s %-12s %s"%('Base','Size','Path')
        
            for module in modules:
                if not process_address_space.is_valid_address(module):
                    continue
                path = module_path(process_address_space, types, module)
                if path is None:
                    path = "%-10s  " % ('UNKNOWN')
                
                base = module_base(process_address_space, types, module)
                if base is None:
                    base = "%-10s  " % ('UNKNOWN')
                else:
                    base = "0x%-10x" % (base)
                
                size = module_size(process_address_space, types, module)
                if size is None:
                    size = "%-10s  " % ('UNKNOWN')
                else:
                    size = "0x%-10x" % (size)
                
                print "%s %s %s"%(base,size,path)            
            
            print

###################################
#  connections - List open connections
###################################
def get_connections(cmdname, argv):
    """
    Function prints a list of open connections
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    star_line = '*'*72

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
    
    connections = tcb_connections(addr_space, types, symtab)

    if len(connections) > 0:
        print "%-25s %-25s %-6s"%('Local Address','Remote Address','Pid')

    for connection in connections:
        
        if not addr_space.is_valid_address(connection):
            continue

        pid     = connection_pid(addr_space, types, connection)
        lport   = connection_lport(addr_space, types, connection)
        laddr   = connection_laddr(addr_space, types, connection)
        rport   = connection_rport(addr_space, types, connection)
        raddr   = connection_raddr(addr_space, types, connection)

        local = "%s:%d"%(laddr,lport)
        remote = "%s:%d"%(raddr,rport)

        print "%-25s %-25s %-6d"%(local,remote,pid)

###################################
#  sockets - List open sockets
###################################
def get_sockets(cmdname, argv):
    """
    Function prints a list of open sockets.
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
    
    sockets = open_sockets(addr_space, types, symtab)

    if len(sockets) > 0:
        print "%-6s %-6s %-6s %-26s"%('Pid','Port','Proto','Create Time')

    for socket in sockets:

        if not addr_space.is_valid_address(socket):
            continue

        pid   = socket_pid(addr_space, types, socket)
        proto = socket_protocol(addr_space, types, socket)
        port  = socket_local_port(addr_space, types, socket)
        time  = socket_create_time(addr_space, types, socket)
        
        print "%-6d %-6d %-6d %-26s"%(pid,port,proto,format_time(time))

###################################
#  files - List open files
###################################
def print_entry_file(addr_space, types, entry):

    if not addr_space.is_valid_address(entry):
    	return

    obj = handle_entry_object(addr_space, types, entry)
    if obj is None:
        return
    
    if addr_space.is_valid_address(obj):
        if is_object_file(addr_space, types, obj):
            file = object_data(addr_space, types, obj)
            fname = file_name(addr_space, types, file)
            if fname != "":
                print "%-6s %-40s"%("File",fname)

def get_open_files(cmdname, argv):
    """
    Function prints a list of open files for each process.
    """
    htables = []    

    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
               help='EPROCESS Offset (in hex) in physical address space',
               action='store', type='string', dest='offset')

    op.add_option('-p', '--pid',
                  help='Get info for this Pid',
                  action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)

    filename = opts.filename
    pid = opts.pid

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

        ObjectTable = process_handle_table(flat_address_space, types, offset)

        if addr_space.is_valid_address(ObjectTable):
            htables.append(ObjectTable)
        
    else:

        htables = handle_tables(addr_space, types, symtab,pid)


    star_line = '*'*72

    for table in htables:
        if len(htables) > 1:
            print "%s"%star_line

        process_id = handle_process_id(addr_space, types, table)
        if process_id == None:
            continue

        print "Pid: %-6d"%(process_id)

        entries = handle_entries(addr_space, types, table)
        for hentry in entries:
            print_entry_file(addr_space, types, hentry)


###################################
#  strings - identify pid(s) associated with a string
###################################
def print_string(offset, pidlist, string):
    print "%d " % (offset),

    print "[%s:%x" % (pidlist[0][0], pidlist[0][1] | (offset & 0xFFF)),
    
    for i in pidlist[1:]:
        print " %s:%x" % (i[0], (i[1] | (offset & 0xFFF))),

    print "] %s" % string,
    
def get_strings(cmdname, argv):
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--strings', help='(required) File of form <offset>:<string>',
                  action='store', type='string', dest='stringfile')
    opts, args = op.parse_args(argv)

    if opts.stringfile is None:
        op.error("String file (-s) required")

    try:
        strings = open(opts.stringfile, "r")
    except:
        op.error("Invalid or inaccessible file %s" % opts.stringfile)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    all_tasks = process_list(addr_space, types, symtab)

    # dict of form phys_page -> [isKernel, (pid1, vaddr1), (pid2, vaddr2) ...]
    # where isKernel is True or False. if isKernel is true, list is of all kernel addresses
    # ASSUMPTION: no pages mapped in kernel and userland
    reverse_map = {}


    vpage = 0
    while vpage < 0xFFFFFFFF:
        kpage = addr_space.vtop(vpage)
        if not kpage is None:
            if not reverse_map.has_key(kpage):
                reverse_map[kpage] = [True]
            reverse_map[kpage].append(('kernel', vpage))
        vpage += 0x1000

    for task in all_tasks:
        process_id = process_pid(addr_space, types, task)
        process_address_space = process_addr_space(addr_space, types, task, opts.filename)
        vpage = 0
        try:
            while vpage < 0xFFFFFFFF:
                physpage = process_address_space.vtop(vpage)
                if not physpage is None:
                    if not reverse_map.has_key(physpage):
                        reverse_map[physpage] = [False]

                    if not reverse_map[physpage][0]:
                        reverse_map[physpage].append((process_id, vpage))
                vpage += 0x1000
        except:
            continue

    for stringLine in strings:
        (offsetString, string) = stringLine.split(':', 1)
        try:
            offset = int(offsetString)
        except:
            op.error("String file format invalid.")
        if reverse_map.has_key(offset & 0xFFFFF000):
            print_string(offset, reverse_map[offset & 0xFFFFF000][1:], string)


###################################
#  vadinfo - Dump the VAD to file
###################################

def vadinfo(cmdname, argv):
    """
    This function dumps the vad information
    """
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
                  help='EPROCESS Offset (in hex) in physical address space',
                  action='store', type='string', dest='offset')

    op.add_option('-p', '--pid',
                  help='Dump the VAD of the process with this Pid',
                  action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)

    if opts.filename is None:
        op.error("vadinfo -f <filename:required>")
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

        process_id = process_pid(flat_address_space, types, offset)

        if process_address_space is None:
            print "Error obtaining address space for process [%d]" % (process_id)
            return

        VadRoot = process_vadroot(flat_address_space, types, offset)

        if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
            print "VadRoot is not valid"
            return

        vad_info(process_address_space, types, VadRoot)

    else:

        all_tasks = process_list(addr_space, types, symtab)

        if not opts.pid == None:
            all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found"%opts.pid

        star_line = '*'*72

        for task in all_tasks:

            print "%s"%star_line
  
            if not addr_space.is_valid_address(task):
                print "Task address is not valid"
                continue        

            directory_table_base = process_dtb(addr_space, types, task)
   
            process_id = process_pid(addr_space, types, task)

            process_address_space = create_addr_space(addr_space, directory_table_base)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                continue

            print "Pid: %-6d"%(process_id)

            VadRoot = process_vadroot(addr_space, types, task)

            if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
                print "VadRoot is not valid"
                continue

            vad_info(process_address_space, types, VadRoot)

def vaddump(cmdname, argv):
    """
    This function dumps the vad information
    """
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
                 help='EPROCESS Offset (in hex)',
                  action='store', type='string', dest='offset')
    op.add_option('-d', '--directory',
                  help='Output directory',
                  action='store', type='string', dest='dir')
    op.add_option('-p', '--pid',
                  help='Dump the VAD of the process with this Pid',
                  action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)

    if opts.filename is None:
        op.error("vaddump -f <filename:required>")
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

        VadRoot = process_vadroot(flat_address_space, types, offset)

        if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
            print "VadRoot is not valid"
            return

        vad_dump(process_address_space, types, VadRoot, image_file_name, offset, opts.dir)

    else:
        all_tasks = process_list(addr_space, types, symtab)

        if not opts.pid == None:
            all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found"%opts.pid
            
        star_line = '*'*72

        for task in all_tasks:

            print "%s"%star_line

            if not addr_space.is_valid_address(task):
                print "Task address is not valid"
                continue
        
            directory_table_base = process_dtb(addr_space, types, task)
    
            process_address_space = create_addr_space(addr_space, directory_table_base)

            image_file_name = process_imagename(addr_space, types, task)
    
            process_id = process_pid(addr_space, types, task)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                continue

            print "Pid: %-6d"%(process_id)

            VadRoot = process_vadroot(addr_space, types, task)

            if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
                print "VadRoot is not valid"
                continue

            offset = process_address_space.vtop(task)

            vad_dump(process_address_space, types, VadRoot, image_file_name, offset, opts.dir)
      

###################################
#  vadwalk - Print the VadTree
###################################

def vadwalk(cmdname, argv):
    """
    This function dumps the vad information
    """
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
                  help='EPROCESS Offset (in hex)',
                  action='store', type='string', dest='offset')

    op.add_option('-e', '--tree',
                  help='print VAD tree in tree format',
	          action='store_true',dest='tree', default=False)

    op.add_option('-l', '--table',
                  help='print VAD tree in table format',
                  action='store_true',dest='table', default=False)

    op.add_option('-d', '--dot',
                  help='print VAD tree in Dotfile format',
		  action='store_true',dest='dot', default=False)

    op.add_option('-p', '--pid',
                  help='Dump the VAD of the process with this Pid',
                  action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)  


    if opts.filename is None:
        op.error("vadwalk -f <filename:required> [options]")
    else:
        filename = opts.filename    

    tree = opts.tree
    table = opts.table
    dot = opts.dot

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    if opts.tree == False and opts.dot == False:
        opts.table = True

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

        VadRoot = process_vadroot(flat_address_space, types, offset)

        if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
            print "VadRoot is not valid"
            return

        if(opts.table == True):
        
            print "Address  Parent   Left     Right    Start    End      Tag  Flags"
            traverse_vad(None, addr_space, types, VadRoot, print_vad_table, None, None, 0, None)

        elif (opts.tree == True):

            traverse_vad(None, addr_space, types, VadRoot, print_vad_tree, None, None, 0, None)

        elif (opts.dot == True):
            print "digraph processtree {"
            print "graph [rankdir = \"TB\"];"
            traverse_vad(None, addr_space, types, VadRoot, print_vad_dot_prefix, print_vad_dot_infix, None, 0, None) 
            print "}"

        else:
            op.error("Output type required!")

    else:
        all_tasks = process_list(addr_space, types, symtab)

        if not opts.pid == None:
            all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found"%opts.pid

        star_line = '*'*72

        for task in all_tasks:

            print "%s"%star_line    
            
            if not addr_space.is_valid_address(task):
                print "Task address is not valid"
                continue

            directory_table_base = process_dtb(addr_space, types, task)
   
            process_id = process_pid(addr_space, types, task)

            process_address_space = create_addr_space(addr_space, directory_table_base)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                continue

            print "Pid: %-6d"%(process_id)

            VadRoot = process_vadroot(addr_space, types, task)

            if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
                print "VadRoot is not valid"
                continue

            if(opts.table == True):
        
                print "Address  Parent   Left     Right    Start    End      Tag  Flags"
                traverse_vad(None, addr_space, types, VadRoot, print_vad_table, None, None, 0, None)

            elif (opts.tree == True):

                traverse_vad(None, addr_space, types, VadRoot, print_vad_tree, None, None, 0, None)

            elif (opts.dot == True):
                print "digraph processtree {"
                print "graph [rankdir = \"TB\"];"
                traverse_vad(None, addr_space, types, VadRoot, print_vad_dot_prefix, print_vad_dot_infix, None, 0, None) 
                print "}"

            else:
                op.error("Output type required!")


###################################
#  psscan - Scan for EPROCESS objects
###################################

def psscan(cmdname, argv):
    """
    This module scans for EPROCESS objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)

    op.add_option('-d', '--dot',
                  help='Print processes in dot format',
                  action='store_true',dest='dot_format', default=False)

    opts, args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexidecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexidecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"%(filesize))

    else:
        end = filesize

    try:
        if slow == False:
            flat_address_space = FileAddressSpace(filename,fast=True)
        else:
            flat_address_space = FileAddressSpace(filename,fast=False)
    except:
        op.error("Unable to open image file %s" % (filename))
    
    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename,fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space,0,0)
        slow = True

    if opts.dot_format:
        ps_scan_dot(flat_address_space, types, filename, start, end, slow) 
    else:
        ps_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  thrdscan - Scan for ETHREAD objects
###################################

def thrdscan(cmdname, argv):
    """
    This module scans for ETHREAD objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)

    opts, args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexidecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexidecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"% (filesize) )

    else:
        end = filesize

    try:

        if slow == False:
            flat_address_space = FileAddressSpace(filename,fast=True)
        else:
            flat_address_space = FileAddressSpace(filename,fast=False)

    except:
        op.error("Unable to open image file %s" % (filename))
    
    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename,fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space,0,0)
        slow = True

    thrd_scan(flat_address_space, types, filename, start, end, slow) 


###################################
#  sockscan - Scan for socket objects
###################################

def sockscan(cmdname, argv):
    """
    This module scans for socket objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)


    opts, args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexidecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexidecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"%(filesize))

    else:
        end = filesize

    try:

        if slow == False:
            flat_address_space = FileAddressSpace(filename,fast=True)
        else:
            flat_address_space = FileAddressSpace(filename,fast=False)

    except:
        op.error("Unable to open image file %s" % (filename))
   
    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename,fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space,0,0)
        slow = True

    socket_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  connscan - Scan for connection objects
###################################

def connscan(cmdname, argv):
    """
    This module scans for connection objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)

    opts, args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexidecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexidecimal number.")

        if end > filesize:
            sop.error("End of scan is larger than filesize 0x%x"%(filesize))

    else:
        end = filesize

    try:

        if slow == False:
            flat_address_space = FileAddressSpace(filename,fast=True)
        else:
            flat_address_space = FileAddressSpace(filename,fast=False)

    except:
        op.error("Unable to open image file %s" % (filename))

    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename,fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space,0,0)
        slow = True
    
    conn_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  memory map
###################################

def mem_map(cmdname, argv):
 
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
        help='EPROCESS Offset (in hex)',
        action='store', type='string', dest='offset')

    op.add_option('-p', '--pid',
        help='Print the memory map for this Pid',
        action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)

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

###################################
#  module scan
###################################
        
def modscan(cmdname, argv):
    """
    This (Volatility) module scans for (Windows) modules
    """
    
    op = get_standard_parser(cmdname)
   
    op.add_option('-s', '--start',
        help='Start of scan (in hex)',
        action='store', type='string', dest='start')

    op.add_option('-e', '--end',
        help='End of scan (in hex)',
        action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)
    
    opts, args = op.parse_args(argv)
    
    slow = opts.slow
    
    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  
    
    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexidecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexidecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"%(filesize))
    else:
        end = filesize
       
    try:  
        flat_address_space = FileAddressSpace(filename,fast=True)
    except:
        op.error("Unable to open image file %s" % (filename))
 
    # Find a dtb value
    if opts.base is None:
        sysdtb = find_dtb(flat_address_space, types)
    else:
        try:
            sysdtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexidecimal number.")


    if is_crash_dump(filename) == True:
        sub_addr_space = WindowsCrashDumpSpace32(flat_address_space,0,0)
    else:
        sub_addr_space = flat_address_space

    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename,fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space,0,0)
        slow = True

    meta_info.set_dtb(sysdtb)
    kaddr_space = load_pae_address_space(filename, sysdtb)
    if kaddr_space is None:
        kaddr_space = load_nopae_address_space(filename, sysdtb)
    meta_info.set_kas(kaddr_space)

    module_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  dumpchk
###################################
def dump_chk(cmdname, argv):
    """
    Print crash dump information
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  

    fileAS = FileAddressSpace(opts.filename)
    crashAS = WindowsCrashDumpSpace32(fileAS,0,0)

    print "DUMP_HEADER32:"
    print "MajorVersion		0x%08x"% \
        crashAS.get_majorversion()
    print "MinorVersion		0x%08x"% \
        crashAS.get_minorversion()	
    print "KdSecondaryVersion	0x%08x"% \
        crashAS.get_kdsecondaryversion()
    print "DirectoryTableBase	0x%08x"% \
        crashAS.get_directorytablebase()
    print "PfnDataBase		0x%08x"% \
        crashAS.get_pfndatabase()
    print "PsLoadedModuleList	0x%08x"% \
        crashAS.get_psloadedmodulelist()
    print "PsActiveProcessHead	0x%08x"% \
        crashAS.get_psactiveprocesshead()
    print "MachineImageType	0x%08x"% \
        crashAS.get_machineimagetype()
    print "NumberProcessors	0x%08x"% \
        crashAS.get_numberprocessors()
    print "BugCheckCode		0x%08x"% \
        crashAS.get_bugcheckcode()
    print "PaeEnabled		0x%08x"% \
        crashAS.get_paeenabled()
    print "KdDebuggerDataBlock	0x%08x"% \
        crashAS.get_kddebuggerdatablock()
    print "ProductType		0x%08x"% \
        crashAS.get_producttype()
    print "SuiteMask		0x%08x"% \
        crashAS.get_suitemask()
    print "WriterStatus		0x%08x"% \
        crashAS.get_writerstatus()
    
    print 
    print "Physical Memory Description:"
    print "Number of runs: %d"%crashAS.get_number_of_runs()
    print "FileOffset	Start Address	Length"
    foffset=0x1000
    for run in crashAS.runs:
        print "%08x	%08x	%08x"%(foffset,run[0]*0x1000,run[1]*0x1000)
        foffset += (run[1] * 0x1000)
    print "%08x	%08x"%(foffset-0x1000,((run[0]+run[1]-1)*0x1000))


###################################
#  user dump
###################################

def mem_dump(cmdname, argv):
 
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
        help='EPROCESS Offset (in hex)',
        action='store', type='string', dest='offset')

    op.add_option('-p', '--pid',
        help='Dump the address space for this Pid',
        action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)

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

        entries = process_address_space.get_available_pages()

        #ofilename = image_file_name + ".dmp"
        ofilename = opts.offset + ".dmp"

        # Check to make sure file can open
        ohandle=open(ofilename,'wb')

        for entry in entries:
            data = process_address_space.read(entry[0],entry[1])
            ohandle.write("%s"%data)

        ohandle.close()

    else:

        if opts.pid == None:
            op.error("Please specify pid or offset: usrdmp -p <PID> -o <offset>")

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

        image_file_name = process_imagename(process_address_space, types, task[0])

        entries = process_address_space.get_available_pages()

        #ofilename = image_file_name + ".dmp"
        ofilename = str(opts.pid) + ".dmp"

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

###################################
#  hibinfo - print hiberfil.sys meta information and convert
###################################
def hibinfo(cmdname, argv):
    """
    Print hiberfile.sys meta information and convert to raw image
    """
    PagesListHead = {}
    op = get_standard_parser(cmdname)

    op.add_option('-q', '--quick',
                  help='Only dump header information',
	          action='store_true',dest='quick', default=False)
    
    op.add_option("-d", "--dump", help="save dd-style dump to FILE",
            metavar="FILE", dest="dump")
    opts, args = op.parse_args(argv)

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  

    if opts.dump is None and opts.quick == False:
        op.error("Dump file is required")
    else:
        dumpfile = opts.dump

    fileAS = FileAddressSpace(opts.filename)
    
    hiberAS = WindowsHiberFileSpace32(fileAS,0,0)

    if not hiberAS:
        print "Error: Failed to open file"
        return 

    print "Signature: %s"%hiberAS.get_signature()

    print "SystemTime: %s"%hiberAS.get_system_time()

    print
    print "Control registers flags"

    print "CR0: %08x"%hiberAS.CR0

    print "CR0[PAGING]: %d"%hiberAS.is_paging() 

    print "CR3: %08x"%hiberAS.CR3

    print "CR4: %08x"%hiberAS.CR4

    print "CR4[PSE]: %d"%hiberAS.is_pse()

    print "CR4[PAE]: %d"%hiberAS.is_pae()

    (major,minor,build) =  hiberAS.get_version()

    print
    print "Windows Version is %d.%d (%d)"%(major,minor,build)
    print

    if opts.quick:
        return

    print "Physical Memory dump."

    try:
        dmp = open(dumpfile,'wb')
    except IOError:
        print "Error opening file [%s]"% (dumpfile)
        return

    hiberAS.convert_to_raw(dmp)
    dmp.close()
    print "Memory dump successfuly dumped."

###################################
#  raw2dmp - raw2dump raw image to crash dump
###################################
def raw2dmp(cmdname, argv):
    """
    This module generates a crash dump from a image of ram
    """
    op = get_standard_parser(cmdname)
    
    op.add_option('-o', '--output', help='Output file',
                  action='store', type='string', dest='outfile')

    opts, args = op.parse_args(argv)

    if (opts.outfile is None):
        op.error("Output file is required")  

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
        
    dd_to_crash(addr_space, types, symtab, opts)


###################################
#  dmp2raw - Convert a crash dump into a flat address space
###################################
def dmp2raw(cmdname, argv):
    """
    This function creates a crash dump
    """
    op = get_standard_parser(cmdname)
    
    # add extra arg for the output file
    op.add_option('-o', '--output', help='Output file',
                  action='store', type='string', dest='outfile')

    opts, args = op.parse_args(argv)

    if (opts.outfile is None):
        op.error("Output file is required")  

    filename = opts.filename

    try:
	    flat_address_space = FileAddressSpace(filename,fast=False)
    except:
        op.error("Unable to open image file %s" % (filename))


    crash_to_dd(flat_address_space, types, opts.outfile)  


###################################
#  registry keys - List open registry keys
###################################

def get_open_keys(cmdname, argv):
    """
    Function prints a list of open keys for each process.
    """
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
               help='EPROCESS Offset (in hex) in physical address space',
               action='store', type='string', dest='offset')

    op.add_option('-p', '--pid',
                  help='Get info for this Pid',
                  action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)

    filename = opts.filename
    pid = opts.pid

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

        ObjectTable = process_handle_table(flat_address_space, types, offset)

        if addr_space.is_valid_address(ObjectTable):
            htables = [ObjectTable]
        
    else:

        htables = handle_tables(addr_space, types, symtab,pid)

    star_line = '*'*72

    for table in htables:
        if len(htables) > 1:
            print "%s"%star_line

        process_id = handle_process_id(addr_space, types, table)
        if process_id == None:
            continue

        print "Pid: %-6d"%(process_id)

        entries = handle_entries(addr_space, types, table)
        for hentry in entries:
            ek = print_entry_keys(addr_space, types, hentry)
            if ek != None:
                print ek


###################################
# procdump - Dump a process to an executable image
###################################
def procdump(cmdname,argv):
    """
    This function dumps a process to a PE file.
    """
    op = get_standard_parser(cmdname)
    op.add_option('-o', '--offset',
                  help='EPROCESS Offset (in hex) in physcial address space',
                  action='store', type='string', dest='offset')
    op.add_option('-p', '--pid',
                  help='Dump the process with this Pid',
                  action='store', type='int', dest='pid')
    op.add_option('-m', '--mode',
                  help=('strategy to use when saving executable. Use "disk" to '
                        'save using disk-based section sizes, "mem" for memory-'
                        'based sections. (default: "mem")'),
                  action='store', type='string', default="mem", dest='mode')
    op.add_option('-u', '--unsafe',
                  help='do not perform sanity checks on sections when dumping',
                  action='store_false', default=True, dest='safe')
    opts, args = op.parse_args(argv)

    if opts.filename is None:
        op.error("procdump -f <filename:required>")
    else:
        filename = opts.filename    

    if opts.mode == "disk":
        rebuild_exe = rebuild_exe_dsk
    elif opts.mode == "mem":
        rebuild_exe = rebuild_exe_mem
    else:
        op.error('"mode" must be one of "disk" or "mem"')

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    if not opts.offset is None:
        try:
            offset = int(opts.offset, 16)
        except:
            op.error("EPROCESS offset must be a hexadecimal number.")
        
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
        
        peb = process_peb(flat_address_space, types, offset)

        if peb == None:
            print "Error: PEB not memory resident for process [%d]" % (process_id)
            return

        img_base = read_obj(process_address_space, types, ['_PEB', 'ImageBaseAddress'], peb)
  
        if img_base == None:
            print "Error: Image base not memory resident for process [%d]" % (process_id)
            return


        if process_address_space.vtop(img_base) == None:
            print "Error: Image base not memory resident for process [%d]" % (process_id)
            return

        print "Dumping %s, pid: %-6d output: %s"%(image_file_name,process_id,"executable.%d.exe" % (process_id))
        of = open("executable.%d.exe" % (process_id), 'wb')
        rebuild_exe(process_address_space, types, img_base, of, opts.safe)
        of.close()
    else:
        all_tasks = process_list(addr_space, types, symtab)

        if not opts.pid == None:
            all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found"%opts.pid

        star_line = '*'*72

        for task in all_tasks:

            print star_line        

            directory_table_base = process_dtb(addr_space, types, task)
   
            process_id = process_pid(addr_space, types, task)

            process_address_space = create_addr_space(addr_space, directory_table_base)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                continue

            image_file_name = process_imagename(process_address_space, types, task)

            peb = process_peb(process_address_space, types, task)
            
            if peb == None:
                print "Error: PEB not memory resident for process [%d]" % (process_id)
                continue

            img_base = read_obj(process_address_space, types, ['_PEB', 'ImageBaseAddress'], peb)

            
            if img_base == None:
                print "Error: Image base not memory resident for process [%d]" % (process_id)
                continue

            if process_address_space.vtop(img_base) == None:
                print "Error: Image base not memory resident for process [%d]" % (process_id)
                continue

            print "Dumping %s, pid: %-6d output: %s"%(image_file_name,process_id,"executable.%d.exe" % (process_id))

            of = open("executable.%d.exe" % (process_id), 'wb')
            try:
                rebuild_exe(process_address_space, types, img_base, of, opts.safe)
            except ValueError,ve:
                print "Unable to dump executable; sanity check failed:"
                print "  ", ve
                print "You can use -u to disable this check."
            of.close()


###################################
#  The following new scanning modules make use
#  of the new scanning infrastructure.
###################################

def connscan2(cmdname, argv):
 
    scanners = []
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  

    flat_address_space = FileAddressSpace(filename,fast=True)

    try:
        flat_address_space = FileAddressSpace(filename,fast=True)
    except:
        op.error("Unable to open image file %s" % (filename))

    meta_info.set_datatypes(types)

    # Determine the applicable address space
    search_address_space = find_addr_space(flat_address_space, types)

    # Find a dtb value
    if opts.base is None:
        sysdtb = get_dtb(search_address_space, types)
    else:
        try:
            sysdtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexidecimal number.")

    meta_info.set_dtb(sysdtb)
    kaddr_space = load_pae_address_space(filename, sysdtb)
    if kaddr_space is None:
        kaddr_space = load_nopae_address_space(filename, sysdtb)
    meta_info.set_kas(kaddr_space)

    print "Local Address             Remote Address            Pid   \n"+ \
          "------------------------- ------------------------- ------ \n";

    scanners.append(PoolScanConnFast2(search_address_space))
    scan_addr_space(search_address_space,scanners)


def sockscan2(cmdname, argv):
 
    scanners = []
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  

    try:
        flat_address_space = FileAddressSpace(filename,fast=True)
    except:
        op.error("Unable to open image file %s" % (filename))
    
    meta_info.set_datatypes(types)

    # Determine the applicable address space
    search_address_space = find_addr_space(flat_address_space, types)

    # Find a dtb value
    if opts.base is None:
        sysdtb = get_dtb(search_address_space, types)
    else:
        try:
            sysdtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexidecimal number.")

    meta_info.set_dtb(sysdtb)
    kaddr_space = load_pae_address_space(filename, sysdtb)
    if kaddr_space is None:
        kaddr_space = load_nopae_address_space(filename, sysdtb)
    meta_info.set_kas(kaddr_space)

    print "PID    Port   Proto  Create Time                Offset \n"+ \
    "------ ------ ------ -------------------------- ----------\n";

    scanners.append(PoolScanSockFast2(search_address_space))
    scan_addr_space(search_address_space,scanners)

def modscan2(cmdname, argv): 
    scanners = []
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  

    try:
        flat_address_space = FileAddressSpace(filename,fast=True)
    except:
        op.error("Unable to open image file %s" % (filename))
    
    meta_info.set_datatypes(types)

    # Determine the applicable address space
    search_address_space = find_addr_space(flat_address_space, types)

    # Find a dtb value
    if opts.base is None:
        sysdtb = get_dtb(search_address_space, types)
    else:
        try:
            sysdtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexidecimal number.")

    meta_info.set_dtb(sysdtb)
    kaddr_space = load_pae_address_space(filename, sysdtb)
    if kaddr_space is None:
        kaddr_space = load_nopae_address_space(filename, sysdtb)
    meta_info.set_kas(kaddr_space)

    print "%-50s %-12s %-8s %s \n"%('File','Base', 'Size', 'Name')

    scanners.append((PoolScanModuleFast2(search_address_space)))
    scan_addr_space(search_address_space,scanners)

def thrdscan2(cmdname, argv):
    scanners = []
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  

    try:
        flat_address_space = FileAddressSpace(filename,fast=True)
    except:
        op.error("Unable to open image file %s" % (filename))
    
    meta_info.set_datatypes(types)

    # Determine the applicable address space
    search_address_space = find_addr_space(flat_address_space, types)

    # Find a dtb value
    if opts.base is None:
        sysdtb = get_dtb(search_address_space, types)
    else:
        try:
            sysdtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexidecimal number.")

    meta_info.set_dtb(sysdtb)
    kaddr_space = load_pae_address_space(filename, sysdtb)
    if kaddr_space is None:
        kaddr_space = load_nopae_address_space(filename, sysdtb)
    meta_info.set_kas(kaddr_space)

    print "No.  PID    TID    Offset    \n"+ \
          "---- ------ ------ ----------\n";

    scanners.append((PoolScanThreadFast2(search_address_space)))
    scan_addr_space(search_address_space,scanners)

def psscan2(cmdname, argv):
    scanners = []
    op = get_standard_parser(cmdname)
    op.add_option('-d', '--dot',
        help='Print processes in dot format',
        action='store_true',dest='dot_format', default=False)
    opts, args = op.parse_args(argv)

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  

    try:
        flat_address_space = FileAddressSpace(filename,fast=True)
    except:
        op.error("Unable to open image file %s" % (filename))


    meta_info.set_datatypes(types)

    # Determine the applicable address space
    search_address_space = find_addr_space(flat_address_space, types)

    # Find a dtb value
    if opts.base is None:
        sysdtb = get_dtb(search_address_space, types)
    else:
        try:
            sysdtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexidecimal number.")

    meta_info.set_dtb(sysdtb)
    kaddr_space = load_pae_address_space(filename, sysdtb)
    if kaddr_space is None:
        kaddr_space = load_nopae_address_space(filename, sysdtb)
    meta_info.set_kas(kaddr_space)

    if opts.dot_format:
        print "digraph processtree { \n" + \
              "graph [rankdir = \"TB\"];"
        scanners.append((PoolScanProcessDot(search_address_space)))
    else:
        print "PID    PPID   Time created             Time exited              Offset     PDB        Remarks\n"+ \
          "------ ------ ------------------------ ------------------------ ---------- ---------- ----------------\n";
        scanners.append((PoolScanProcessFast2(search_address_space)))

    scan_addr_space(search_address_space,scanners)

    if opts.dot_format:
        print "}"
