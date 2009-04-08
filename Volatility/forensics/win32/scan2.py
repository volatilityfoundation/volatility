# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Derived from source in PyFlag developed by:
# Copyright 2004: Commonwealth of Australia.
# Michael Cohen <scudette@users.sourceforge.net> 
# David Collett <daveco@users.sourceforge.net>
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
#
# Special thanks to Michael Cohen for ideas and comments!
#


"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems.
"""

import os
from struct import unpack
from forensics.object import *
from forensics.win32.datetime import *
from forensics.win32.info import *
from forensics.win32.tasks import *
from forensics.win32.network import *
from forensics.win32.modules import *
from forensics.x86 import *
import forensics.win32.meta_info as meta_info


class BaseMemoryScanner:
    """ This is the actual scanner class that will be instantiated
        for each address space to be analyzed. Within Volatility,
        all scans are performed over an address space, which is used
        to simulate random access over a logical view of data.  
    """

    def __init__(self, poffset, outer):

        """
        @arg poffset: The offset of the data being scanned
        @arg outer:   This references the generator object 

        """
        self.poffset = poffset
        self.ignore = False        
        self.outer = outer

    def process(self, data, offset, metadata={}):
        """ process the chunk of data.

        This function is given a chunk of data from the address space.
                
        @arg data: Some limited amount of data from the address space. The
        size of the data is unspecified.

        @arg metadata: A dict specifying meta data that was deduced
        about this data from other scanners. Scanners may add meta
        data to this dict in order to indicate certain facts to other
        scanners about this data.  
	""" 
        pass

    def finish(self):
        """ all data has been provided to process, finish up.

        Note that this signals that the chunk has been processed.
        """
        pass

class GenMemScanObject:
    """ Abstract Base class for scanner Factories.
    
    The Scanner Object is a specialised class for producing scanner
    objects. It will be instantiated once at the begining of the run,
    and destroyed at the end of the run.
    """
    ## Should this scanner be on by default?
    default=False

    ## This is a list of scanner names which we depend on. Depending
    ## on a scanner will force it to be enabled whenever we are
    ## enabled.
    depends = []
    
    def __init__(self,addr_space):
        """ Factory constructor.

        @arg addr_space: An address space object for the address
        space we are about scan 
	""" 
        self.addr_space = addr_space

    def prepare(self):
        """ This is called before the scanner is used.

        Generally the constructor should be very brief (because it
        might be called to reset rather than to actually scan). And
        most work should be done in this method.  
	"""

    def destroy(self):
        """ Final destructor called on the factory to finish the scan operation.

        This is sometimes used to make indexes etc. 
        """
        pass

    class Scan(BaseMemoryScanner):
        """ The Scan class must be defined as an inner class to the factory. """

class SlidingMemoryScanner(BaseMemoryScanner):
    """ A scanner designed to scan buffers of data in memory.

    This scanner implements a sliding window, i.e. each buffer scanned
    begins with OVERLAP/BUFFERSIZE from the previous buffer. This
    allows matches that are broken across a block boundary.  
    """

    #windowsize=8

    def __init__(self, poffset, outer, window_size=8):
        BaseMemoryScanner.__init__(self, poffset,outer)
        self.window = ''
        self.offset=0
        self.outer = outer
        self.window_size = window_size

    def process(self, data, offset, metadata=None):
        buf = self.window + data
        self.as_offset = self.offset
        self.process_buffer(buf,self.offset,metadata)
        self.offset += len(buf)
        self.window = buf[-self.window_size:]
        self.offset -= len(self.window)

    def process_buffer(self,buf,offset):
        """ This abstract method should implement the actual scanner.
  
        @arg buf: The chunk of data to be analyzed.

        @arg offset: The actual offset within the address space.

        """

def scan_addr_space(addr_space,scan_objects):
    """ Given an address space and a list of scan_objects, this
    function scans the address space using the scan_objects

    @arg addr_space: The address space to scan
    @arg scan_objects: A list of scan_objects to search for across
    the address space 
    """

    # BUFFSIZE was chosen so that data would be aligned
    # on 8 bytes.
    #
    # CHUNKSIZE was chosen so that we will process
    # a 4KB page of memory at a time. This has a number of
    # advantages. One of which being the common page size on
    # IA32 machines.
    

    BUFFSIZE = 1024 * 1024 * 10
    CHUNKSIZE = 0x1000

    objs = []
    for c in scan_objects:
        objs.append(c.Scan(addr_space, c))

    if len(objs)==0: return

    as_offset = 0
    while 1:
        try:
            data = addr_space.zread(as_offset,BLOCKSIZE)
            if not data: break
        except IOError,e:
            break

        poffset = 0
        while poffset < BLOCKSIZE:
            chunk = data[poffset:poffset+CHUNKSIZE]
            metadata = {}
            
            # call process method of each class
            # First let's check to see if anyone 
            # is even interested

            interest = 0

            for o in objs:
                if not o.ignore:
                    interest+=1

            if not interest:
                break
        
            for o in objs:
                try:
                    if not o.ignore:
                        interest+=1
                        o.process(chunk,as_offset+poffset, metadata=metadata)

                except Exception,e:
                    print "Scanner (%s) on Offset %d Error: %s" %(o,as_offset,e)
                    raise
     
            poffset+=CHUNKSIZE
        
        # All the CHUNKS of data from this read have been
        # processed. At this point we call the finish method
        # before performing the next read. For example, this may
        # be a time when you would like to batch database operations.

        for o in objs:
            try:
                o.finish()
            except Exception,e:
                print "Scanner (%s) on Offset %d Error: %s" %(o,as_offset,e)
        as_offset+=len(data)

    return objs

class PoolScanner(SlidingMemoryScanner):
    
    def __init__(self, poffset, outer):
        SlidingMemoryScanner.__init__(self, poffset, outer, outer.pool_size)
        self.data_types = meta_info.DataTypes
        self.constraints = []
        self.climit = None     
        self.matches = []

    def format_time(self,time):
        ts=strftime("%a %b %d %H:%M:%S %Y",gmtime(time))
        return ts

    def set_limit(self,limit):
        self.climit = limit

    def get_limit(self):
        if self.climit == None:
             return len(self.constraints)
        elif self.climit > len(self.constraints):
             return len(self.constraints)
        else:
             return self.climit

    def get_blocksize(self, buff, found):
        pool_hdr_val = read_obj_from_buf(buff,self.data_types, \
            ['_POOL_HEADER', 'Ulong1'],found-4)
        if pool_hdr_val == None:
            return None

        BlockSize = (pool_hdr_val >> 16) & 0x1FF  
        
        return BlockSize
        
    def get_poolsize(self, buff, free):
        BlockSize = self.get_blocksize(buff, free)
        
        if BlockSize == None:
            return None
            
        return BlockSize * 8 

    def check_blocksize_geq(self, buff, found):
        pool_size = self.get_poolsize(buff, found)
          
        if pool_size >= self.outer.pool_size:
            return True
        
        return False

    def check_blocksize_equal(self, buff, found):
        pool_size = self.get_poolsize(buff, found)
 
        if pool_size == self.outer.pool_size:
            return True

        return False

    def get_pooltype(self, buff, found):
        data_types = meta_info.DataTypes
        pool_hdr_val = read_obj_from_buf(buff, self.data_types, \
            ['_POOL_HEADER', 'Ulong1'], found-4)
        if pool_hdr_val == None:
            return False

        PoolType = (pool_hdr_val >> 16) & 0xFFFF
        PoolType = (PoolType & 0xFE00) >> 9    
        
        return PoolType   

    def check_paged_pooltype(self, buff, found):
        return self.check_pooltype_paged(buff, found)

    def check_pooltype(self, buff, found):
        return self.check_pooltype_nonpaged_or_free(buff, found)
        
    def check_pooltype_free(self, buff, found):
        PoolType = self.get_pooltype(buff, free)
        
        if PoolType == 0:
            return True
        
        return False
        
    def check_pooltype_nonfree(self, buff, found):
        PoolType = self.get_pooltype(buff, free)
        
        if PoolType != 0:
            return True
        
        return False  

    def check_pooltype_nonpaged(self, buff, found):
        PoolType = self.get_pooltype(buff, found)
        
        if ((PoolType > 0) and ((PoolType % 2) == 1)):
            return True

        return False

    def check_pooltype_nonpaged_or_free(self, buff, found):
        PoolType = self.get_pooltype(buff, found)
        
        if ((PoolType == 0) or ((PoolType % 2) == 1)):
            return True

        return False
                
    def check_pooltype_paged(self, buff, found):
        PoolType = self.get_pooltype(buff, found)
        
        if ((PoolType > 0) and ((PoolType % 2) == 0)):
            return True

        return False

    def check_pooltype_paged_or_free(self, buff, found):
        PoolType = self.get_pooltype(buff, found)
        
        if ((PoolType == 0) or ((PoolType % 2) == 0)):
            return True

        return False

    def get_poolindex(self, buff, found):
        data_types = meta_info.DataTypes
        pool_hdr_val = read_obj_from_buf(buff,self.data_types, \
            ['_POOL_HEADER', 'Ulong1'],found-4)
        if pool_hdr_val == None:
            return False   

        PoolIndex = (pool_hdr_val) & 0xFFFF
        PoolIndex = (PoolIndex & 0xFE00) >> 9 
        
        return PoolIndex
                
    def check_poolindex(self, buff, found):
        return self.check_poolindex_zero(buff, found)
        
    def check_poolindex_zero(self, buff, found):
        PoolIndex = self.get_poolindex(buff, found)
    
        if PoolIndex == 0:
            return True
            
        return False
        
    def check_poolindex_nonzero(self, buff, found):
        PoolIndex = self.get_poolindex(buff, found)
    
        if PoolIndex != 0:
            return True
            
        return False
                
    def check_addr(self,buff,found):
       cnt = 0
       for func in self.constraints:
           val = func(buff,found)
           if val == True:
              cnt = cnt+1
       return cnt

    def add_constraint(self,func):
        self.constraints.append(func)

    def object_offset(self,found):
        return (found - 4) + obj_size(self.data_types,'_POOL_HEADER')
       
    def object_action(self,buff,found):
        """ If constraints are met, perform this action.
        """
        pass
                     
    def process_buffer(self,buff,poffset,metadata=None):

            found = 0
            while 1:
                found = buff.find(self.outer.pool_tag, found+1)
                if found > 0:

                     oaddr = self.object_offset(found)+self.as_offset

                     if oaddr in self.matches:
                         continue                           

                     match_count = self.check_addr(buff,found)
                    
                     if match_count == self.get_limit():
                         ooffset = self.object_offset(found)
                         self.object_action(buff,ooffset)
                         self.matches.append(oaddr)
                                             
                else:
                    break

class PoolScanConnFast2(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x54\x43\x50\x54" 
        self.pool_size = 0x198

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_blocksize_geq)
            self.add_constraint(self.check_pooltype)
            self.add_constraint(self.check_poolindex)

        def object_action(self,buff,object_offset):
            """
            In this instance, the object action is to print to
            stdout
            """
            pid = read_obj_from_buf(buff, self.data_types, \
	        ['_TCPT_OBJECT', 'Pid'], object_offset)
            lport = ntohs(read_obj_from_buf(buff, self.data_types, \
	        ['_TCPT_OBJECT', 'LocalPort'], object_offset))
            laddr = read_obj_from_buf(buff, self.data_types, \
	        ['_TCPT_OBJECT', 'LocalIpAddress'], object_offset)
            laddr = inet_ntoa(struct.pack('=L',laddr))
            rport = ntohs(read_obj_from_buf(buff, self.data_types, \
	        ['_TCPT_OBJECT', 'RemotePort'], object_offset))
            raddr = read_obj_from_buf(buff, self.data_types, \
	        ['_TCPT_OBJECT', 'RemoteIpAddress'], object_offset)
            raddr = inet_ntoa(struct.pack('=L',raddr))

            local = "%s:%d"%(laddr,lport)
            remote = "%s:%d"%(raddr,rport)

            print "%-25s %-25s %-6d"%(local,remote,pid)

class PoolScanSockFast2(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x54\x43\x50\x41" 
        self.pool_size = 0x170
	#self.pool_size = 0x158

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_blocksize_equal)
            self.add_constraint(self.check_pooltype)
            self.add_constraint(self.check_poolindex)
            self.add_constraint(self.check_socket_create_time)

        def check_socket_create_time(self, buff, found):
            soffset = self.object_offset(found)

            time = read_time_buf(buff,self.data_types,\
                ['_ADDRESS_OBJECT', 'CreateTime'],soffset)

            if time == None:
                return False

            if time > 0:
                return True
            return False
            
        def object_action(self,buff,object_offset):
            """
            In this instance, the object action is to print to
            stdout
            """
            pid = read_obj_from_buf(buff, self.data_types, \
                ['_ADDRESS_OBJECT', 'Pid'], object_offset)
            proto = read_obj_from_buf(buff, self.data_types, \
                ['_ADDRESS_OBJECT', 'Protocol'], object_offset)
            port = ntohs(read_obj_from_buf(buff, self.data_types, \
                ['_ADDRESS_OBJECT', 'LocalPort'], object_offset))
           
            time = read_time_buf(buff,self.data_types,\
                ['_ADDRESS_OBJECT', 'CreateTime'],object_offset)

            ooffset = self.as_offset + object_offset
            try:
                print "%-6d %-6d %-6d %-26s 0x%0.8x"%(pid,port,proto, \
                    self.format_time(time),ooffset)
            except:
                return

class PoolScanModuleFast2(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x4D\x6D\x4C\x64" 
        self.pool_size = 0x4c

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_blocksize_geq)
            self.add_constraint(self.check_pooltype)
            self.add_constraint(self.check_poolindex)

        def module_pool_imagename(self, buff, mod_offset):
            addr_space = meta_info.KernelAddressSpace
            name_buf = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'FullDllName', 'Buffer'], mod_offset)
            name_buf_len = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'FullDllName', 'Length'], mod_offset)
                     
            readBuf = read_string(addr_space, self.data_types, ['char'], \
                name_buf, name_buf_len)
            if readBuf is None:
                imagename = ""

            try:
                imagename = readBuf.decode('UTF-16').encode('ascii', 'backslashreplace')
            except:
                imagename = ""

            return imagename

        def module_pool_modulename(self, buff, mod_offset):
            addr_space = meta_info.KernelAddressSpace
            name_buf = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'BaseDllName', 'Buffer'], mod_offset)
            name_buf_len = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'BaseDllName', 'Length'], mod_offset)
                     
            readBuf = read_string(addr_space, self.data_types, ['char'], \
                name_buf, name_buf_len)
            if readBuf is None:
                modulename = ""

            try:
                modulename = readBuf.decode('UTF-16').encode('ascii', 'backslashreplace')
            except:
                modulename = ""

            return modulename
        

        def object_action(self,buff,object_offset):
            """
            In this instance, the object action is to print to
            stdout
            """
            system_addr_space = meta_info.KernelAddressSpace

            baseaddr = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'DllBase'], object_offset)
            imagesize = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'SizeOfImage'], object_offset)

            imagename   = self.module_pool_imagename(buff, object_offset)
            modulename  = self.module_pool_modulename(buff, object_offset)             
            print "%-50s 0x%010x 0x%06x %s" % \
                (imagename, baseaddr, imagesize, modulename)

class PoolScanProcessFast2(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x50\x72\x6F\xE3"
        self.pool_size = 0x280

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_blocksize_geq)
            self.add_constraint(self.check_pooltype)
            self.add_constraint(self.check_poolindex)
            self.add_constraint(self.check_dtb)
            self.add_constraint(self.check_dtb_aligned)
            self.add_constraint(self.check_thread_list)

        def check_dtb(self, buff, found):
            poffset = self.object_offset(found)
            DirectoryTableBase  = read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS', 'Pcb', 'DirectoryTableBase', 0], poffset)
            if DirectoryTableBase == 0:
                return False
            if DirectoryTableBase == None:
                return False
            return True

        def check_dtb_aligned(self, buff, found):
            poffset = self.object_offset(found)
            DirectoryTableBase  = read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS', 'Pcb', 'DirectoryTableBase', 0], poffset)
            if DirectoryTableBase == None:
                return False
            if (DirectoryTableBase % 0x20) != 0:
                return False
            return True

        def object_offset(self,found):
            (offset, tmp) = get_obj_offset(self.data_types, ['_OBJECT_HEADER', 'Body'])
            return (found - 4) + obj_size(self.data_types,'_POOL_HEADER') + offset

        def check_thread_list(self, buff, found):
            kernel = 0x80000000

            poffset = self.object_offset(found)
            thread_list_head_flink =  read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS','ThreadListHead', 'Flink'], poffset)

            if thread_list_head_flink < kernel:
                return False

            thread_list_head_blink =  read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS', 'ThreadListHead', 'Blink'], poffset)

            if thread_list_head_blink < kernel:
                return False

            return True

        def object_action(self,buff,object_offset):
            """
            In this instance, the object action is to print to
            stdout
            """
            UniqueProcessId = read_obj_from_buf(buff, self.data_types, \
               ['_EPROCESS', 'UniqueProcessId'], object_offset)
            InheritedFromUniqueProcessId = read_obj_from_buf(buff, self.data_types, \
               ['_EPROCESS', 'InheritedFromUniqueProcessId'], object_offset)
            DirectoryTableBase  = read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS', 'Pcb', 'DirectoryTableBase', 0], object_offset)
            
            address = self.as_offset + object_offset


            (file_name_offset, current_type) = get_obj_offset(self.data_types,\
                ['_EPROCESS', 'ImageFileName'])
                     
            fnoffset = object_offset+file_name_offset
            string = buff[fnoffset:fnoffset+256]
            if (string.find('\0') == -1):
                ImageFileName = string
            else:
                (ImageFileName, none) = string.split('\0', 1)

            create_time = read_time_buf(buff,self.data_types,\
                ['_EPROCESS', 'CreateTime'],object_offset)

            exit_time = read_time_buf(buff,self.data_types,\
                ['_EPROCESS', 'ExitTime'],object_offset)
            
            if create_time == 0:
                CreateTime = ""
            else:
                CreateTime = self.format_time(create_time)

            if exit_time == 0:
                ExitTime = ""
            else:
                ExitTime = self.format_time(exit_time)

            print "%6d %6d %24s %24s 0x%0.8x 0x%0.8x %-16s"% \
                 (UniqueProcessId,InheritedFromUniqueProcessId,CreateTime,\
                 ExitTime,address,DirectoryTableBase,ImageFileName)

class PoolScanProcessDot(PoolScanProcessFast2):

    class Scan(PoolScanProcessFast2.Scan):
        def format_time(self, time):
            ts=strftime("%H:%M:%S\\n%Y-%m-%d",gmtime(time))
            return ts

        def object_action(self,buff,object_offset):
            """
            In this instance, the object action is to print to
            stdout
            """
            UniqueProcessId = read_obj_from_buf(buff, self.data_types, \
               ['_EPROCESS', 'UniqueProcessId'], object_offset)
            InheritedFromUniqueProcessId = read_obj_from_buf(buff, self.data_types, \
               ['_EPROCESS', 'InheritedFromUniqueProcessId'], object_offset)
            ExitStatus = read_obj_from_buf(buff, self.data_types, \
               ['_EPROCESS', 'ExitStatus'], object_offset)
            DirectoryTableBase  = read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS', 'Pcb', 'DirectoryTableBase', 0], object_offset)
            
            address = self.as_offset + object_offset

            (file_name_offset, current_type) = get_obj_offset(self.data_types,\
                ['_EPROCESS', 'ImageFileName'])
                     
            fnoffset = object_offset+file_name_offset
            string = buff[fnoffset:fnoffset+256]
            if (string.find('\0') == -1):
                ImageFileName = string
            else:
                (ImageFileName, none) = string.split('\0', 1)

            create_time = read_time_buf(buff,self.data_types,\
                ['_EPROCESS', 'CreateTime'],object_offset)

            exit_time = read_time_buf(buff,self.data_types,\
                ['_EPROCESS', 'ExitTime'],object_offset)

            if create_time == 0:
                CreateTime = ""
            else:
                CreateTime = self.format_time(create_time)
                CreateTime = " | started\\n%s"%CreateTime

            if exit_time == 0:
                ExitTime = ""
            else:
                ExitTime = self.format_time(exit_time)

            if not ExitTime == "":
                print "pid%u [label = \"{%u | file ofs\\n0x%x | %s%s | exited\\n%s\\n code %d}\" shape = \"record\" style = \"filled\" fillcolor = \"lightgray\"];"%(UniqueProcessId,UniqueProcessId,address, ImageFileName,CreateTime, ExitTime,ExitStatus)
            else:
                print "pid%u [label = \"{%u | file ofs\\n0x%x | %s%s | running}\" shape = \"record\"];"%(UniqueProcessId,UniqueProcessId,address,ImageFileName,CreateTime)

            print "pid%u -> pid%u []"%(InheritedFromUniqueProcessId,UniqueProcessId)

class PoolScanThreadFast2(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x54\x68\x72\xE5"
        self.pool_size = 0x278

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_blocksize_geq)
            self.add_constraint(self.check_pooltype)
            self.add_constraint(self.check_poolindex)
            self.add_constraint(self.check_threads_process)
            self.add_constraint(self.check_start_address)
            self.add_constraint(self.check_semaphores)

        def check_threads_process(self, buff, found):
            kernel = 0x80000000
            toffset = self.object_offset(found)
            UniqueProcess = read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'Cid', 'UniqueProcess'], toffset)

            ThreadsProcess = read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'ThreadsProcess'], toffset)
            if UniqueProcess != 0 and ThreadsProcess < kernel:
                return False
            return True

        def check_start_address(self, buff, found):
            kernel = 0x80000000
            toffset = self.object_offset(found)

            UniqueProcess = read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'Cid', 'UniqueProcess'], toffset)

            StartAddress = read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'StartAddress'], toffset)

            if UniqueProcess != 0 and StartAddress == 0:
                return False
            return True

        def check_semaphores(self, buff, found):
            toffset = self.object_offset(found)
            UniqueProcess = read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'Cid', 'UniqueProcess'], toffset)

            
            Type =  read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'Tcb', 'SuspendSemaphore','Header','Type'], toffset)


            Size =  read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'Tcb', 'SuspendSemaphore','Header','Size'], toffset)

            if Type == None or Size == None:
                return False

            if(Size != 0x5 and Type != 0x5):
                return False

            Type =  read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'LpcReplySemaphore','Header','Type'], toffset)

            Size =  read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'LpcReplySemaphore','Header','Size'], toffset)

            if Type == None or Size == None:
                return False

            if((Size != 0x5 and Type != 0x5) and UniqueProcess != 0):
                return False

            return True

        def object_offset(self,found):
            (offset, tmp) = get_obj_offset(self.data_types, ['_OBJECT_HEADER', 'Body'])
            return (found - 4) + obj_size(self.data_types,'_POOL_HEADER') + offset

        def object_action(self,buff,object_offset):
            """
            In this instance, the object action is to print to
            stdout
            """
            UniqueProcess =  read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'Cid', 'UniqueProcess'], object_offset)

            UniqueThread =  read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'Cid', 'UniqueThread'], object_offset)                     
            
            address = self.as_offset + object_offset

            print "%6d %6d 0x%0.8x"%(UniqueProcess, UniqueThread, address)
