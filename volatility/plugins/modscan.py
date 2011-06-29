# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
This module implements the fast module scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import volatility.plugins.filescan as filescan
import volatility.scan as scan
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611

class PoolScanModuleFast(scan.PoolScanner):
    preamble = ['_POOL_HEADER', ]

    checks = [ ('PoolTagCheck', dict(tag = 'MmLd')),
               ('CheckPoolSize', dict(condition = lambda x: x > 0x4c)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class ModScan(filescan.FileScan):
    """ Scan Physical memory for _LDR_DATA_TABLE_ENTRY objects
    """

    # Declare meta information associated with this plugin    
    meta_info = dict(
        author = 'Brendan Dolan-Gavitt',
        copyright = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        contact = 'bdolangavitt@wesleyan.edu',
        license = 'GNU General Public License 2.0 or later',
        url = 'http://moyix.blogspot.com/',
        os = 'WIN_32_XP_SP2',
        version = '1.0',
        )

    def calculate(self):
        ## Here we scan the physical address space
        address_space = utils.load_as(self._config, astype = 'physical')

        ## We need the kernel_address_space later
        self.kernel_address_space = utils.load_as(self._config)

        scanner = PoolScanModuleFast()
        for offset in scanner.scan(address_space):
            ldr_entry = obj.Object('_LDR_DATA_TABLE_ENTRY', vm = address_space,
                                  offset = offset)
            yield ldr_entry

    def render_text(self, outfd, data):
        outfd.write("{0:10} {1:50} {2:12} {3:8} {4}\n".format('Offset', 'File', 'Base', 'Size', 'Name'))
        for ldr_entry in data:
            outfd.write("{0:#010x} {1:50} {2:#012x} {3:#08x} {4}\n".format(
                         ldr_entry.obj_offset,
                         self.parse_string(ldr_entry.FullDllName),
                         ldr_entry.DllBase,
                         ldr_entry.SizeOfImage,
                         self.parse_string(ldr_entry.BaseDllName)))

class CheckThreads(scan.ScannerCheck):
    """ Check sanity of _ETHREAD """
    kernel = 0x80000000

    def check(self, found):

        start_of_object = self.address_space.profile.get_obj_size("_POOL_HEADER") + \
                          self.address_space.profile.get_obj_offset('_OBJECT_HEADER', 'Body') - \
                          self.address_space.profile.get_obj_offset('_POOL_HEADER', 'PoolTag')

        ## The preamble needs to be augmented for Windows7
        volmagic = obj.Object("VOLATILITY_MAGIC", 0x0, self.address_space)
        try:
            ObjectPreamble = volmagic.ObjectPreamble.v()
            offsetupdate = self.address_space.profile.get_obj_size(ObjectPreamble)
        except AttributeError:
            offsetupdate = 0

        thread = obj.Object('_ETHREAD', vm = self.address_space,
                           offset = found + start_of_object + offsetupdate)

        #if thread.Cid.UniqueProcess.v() != 0 and \
        #   thread.ThreadsProcess.v() <= self.kernel:
        #    return False

        ## check the start address
        if thread.Cid.UniqueProcess.v() != 0 and \
           thread.StartAddress == 0:
            return False

        ## Check the Semaphores
        if thread.Tcb.SuspendSemaphore.Header.Size != 0x05 and \
               thread.Tcb.SuspendSemaphore.Header.Type != 0x05:
            return False

        if thread.KeyedWaitSemaphore.Header.Size != 0x05 and \
               thread.KeyedWaitSemaphore.Header.Type != 0x05:
            return False

        return True

class PoolScanThreadFast(scan.PoolScanner):
    """ Carve out threat objects using the pool tag """
    preamble = ['_POOL_HEADER', '_OBJECT_HEADER' ]

    def object_offset(self, found, address_space):
        """ This returns the offset of the object contained within
        this pool allocation.
        """

        ## The offset of the object is determined by subtracting the offset
        ## of the PoolTag member to get the start of Pool Object and then
        ## adding the size of the preamble data structures. This done
        ## because PoolScanners search for the PoolTag. 

        pool_base = found - self.buffer.profile.get_obj_offset('_POOL_HEADER', 'PoolTag')

        ## Another data structure is added to the preamble for Win7.
        volmagic = obj.Object("VOLATILITY_MAGIC", 0x0, self.buffer)
        try:
            if not volmagic.ObjectPreamble.v() in self.preamble:
                self.preamble.append(volmagic.ObjectPreamble.v())
        except AttributeError:
            pass

        ## Next we add the size of the preamble data structures
        object_base = pool_base + \
               sum([self.buffer.profile.get_obj_size(c) for c in self.preamble])

        object_base = object_base - \
               (self.buffer.profile.get_obj_size('_OBJECT_HEADER') - \
               self.buffer.profile.get_obj_offset('_OBJECT_HEADER', 'Body'))

        return object_base

    checks = [ ('PoolTagCheck', dict(tag = '\x54\x68\x72\xe5')),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x278)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ('CheckThreads', {}),
               ]

class ThrdScan(ModScan):
    """Scan physical memory for _ETHREAD objects"""
    def calculate(self):
        ## Here we scan the physical address space
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = PoolScanThreadFast()
        for found in scanner.scan(address_space):
            thread = obj.Object('_ETHREAD', vm = address_space,
                               offset = found)

            yield thread

    def render_text(self, outfd, data):
        outfd.write("Offset     PID    TID    Create Time               Exit Time                 StartAddr\n" + \
                    "---------- ------ ------ ------------------------- ------------------------- ----------\n")

        for thread in data:
            outfd.write("{0:#010x} {1:6} {2: <6} {3: <25} {4: <25} {5:#010x}\n".format(thread.obj_offset,
                                                                                     thread.Cid.UniqueProcess,
                                                                                     thread.Cid.UniqueThread,
                                                                                     thread.CreateTime or '',
                                                                                     thread.ExitTime or '',
                                                                                     thread.StartAddress))
