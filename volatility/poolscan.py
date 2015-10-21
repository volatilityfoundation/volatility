# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import volatility.scan as scan
import volatility.constants as constants
import volatility.utils as utils
import volatility.obj as obj
import volatility.registry as registry

#--------------------------------------------------------------------------------
# A multi-concurrent pool scanner 
#--------------------------------------------------------------------------------

class MultiPoolScanner(object):
    """An optimized scanner for pool tags"""

    def __init__(self, needles = None):
        self.needles = needles
        self.overlap = 20

    def scan(self, address_space, offset = None, maxlen = None):

        if offset is None:
            current_offset = 0
        else:
            current_offset = offset

        for (range_start, range_size) in sorted(address_space.get_available_addresses()):
            # Jump to the next available point to scan from
            # self.base_offset jumps up to be at least range_start
            current_offset = max(range_start, current_offset)
            range_end = range_start + range_size

            # If we have a maximum length, we make sure it's less than the range_end
            if maxlen is not None:
                range_end = min(range_end, current_offset + maxlen)

            while (current_offset < range_end):
                # We've now got range_start <= self.base_offset < range_end

                # Figure out how much data to read
                l = min(constants.SCAN_BLOCKSIZE + self.overlap, range_end - current_offset)

                data = address_space.zread(current_offset, l)

                for needle in self.needles:
                    for addr in utils.iterfind(data, needle):
                        # this scanner yields the matched pool tag as well as
                        # the offset, to save the caller from having to perform 
                        # another .read() just to see which tag was matched
                        yield data[addr:addr+4], addr + current_offset

                current_offset += min(constants.SCAN_BLOCKSIZE, l)

#--------------------------------------------------------------------------------
# The main interface / API for concurrent scans 
#--------------------------------------------------------------------------------

class MultiScanInterface(object):
    """An interface into a scanner that can find multiple pool tags
    in a single pass through an address space."""

    def __init__(self, addr_space, scanners = [], scan_virtual = False, show_unalloc = False, use_top_down = False, start_offset = None, max_length = None):
        """An interface into the multiple concurrent pool scanner. 

        @param addr_space: a Volatility address space
        
        @param scanners: a list of PoolScanner classes to scan for. 

        @param scan_virtual: True to scan in virtual/kernel space 
        or False to scan at the physical layer.

        @param show_unalloc: True to skip unallocated objects whose
        _OBJECT_TYPE structure are 0xbad0b0b0. 

        @param use_topdown: True to carve objects out of the pool using
        the top-down approach or False to use the bottom-up trick.

        @param start_offset: the starting offset to begin scanning. 

        @param max_length: the size in bytes to scan from the start. 
        """

        self.scanners = scanners
        self.scan_virtual = scan_virtual
        self.show_unalloc = show_unalloc
        self.use_top_down = use_top_down
        self.start_offset = start_offset
        self.max_length = max_length

        self.address_space = addr_space
        self.pool_alignment = obj.VolMagic(self.address_space).PoolAlignment.v()

    def _check_pool_size(self, check, pool_header):
        """An alternate to the existing CheckPoolSize class. 

        This prevents us from create a second copy of the 
        _POOL_HEADER object which is quite unnecessary. 
        
        @param check: a dictionary of arguments for the check

        @param pool_header: the target _POOL_HEADER to check
        """

        condition = check["condition"]
        block_size = pool_header.BlockSize.v()

        return condition(block_size * self.pool_alignment)

    def _check_pool_type(self, check, pool_header):
        """An alternate to the existing CheckPoolType class. 

        This prevents us from create a second copy of the 
        _POOL_HEADER object which is quite unnecessary. 
        
        @param check: a dictionary of arguments for the check

        @param pool_header: the target _POOL_HEADER to check
        """

        try:
            paged = check["paged"]
        except KeyError:
            paged = False 

        try:
            non_paged = check["non_paged"]
        except KeyError:
            non_paged = False

        try:
            free = check["free"]
        except KeyError:
            free = False 

        return ((non_paged and pool_header.NonPagedPool) or 
                    (free and pool_header.FreePool) or 
                    (paged and pool_header.PagedPool))

    def _check_pool_index(self, check, pool_header):
        """An alternate to the existing CheckPoolIndex class. 

        This prevents us from create a second copy of the 
        _POOL_HEADER object which is quite unnecessary. 
        
        @param check: a dictionary of arguments for the check

        @param pool_header: the target _POOL_HEADER to check
        """

        value = check["value"]
        if callable(value):
            return value(pool_header.PoolIndex)
        else:
            return pool_header.PoolIndex == check["value"]

    def _run_all_checks(self, checks, pool_header):
        """Execute all constraint checks. 

        @param checks: a dictionary with check names as keys and 
        another dictionary of arguments as the values. 

        @param pool_header: the target _POOL_HEADER to check

        @returns False if any checks fail, otherwise True. 
        """

        for check, args in checks:
            if check == "CheckPoolSize":
                if not self._check_pool_size(args, pool_header):
                    return False
            elif check == "CheckPoolType":
                if not self._check_pool_type(args, pool_header):
                    return False
            elif check == "CheckPoolIndex":
                if not self._check_pool_index(args, pool_header):
                    return False
            else:
                custom_check = registry.get_plugin_classes(scan.ScannerCheck)[check](pool_header.obj_vm, **args)
                return custom_check.check(pool_header.PoolTag.obj_offset)
        
        return True

    def scan(self):

        # determine if we're using windows 10
        meta = self.address_space.profile.metadata
        win10 = (meta.get("major"), meta.get("minor")) == (6, 4)

        if self.scan_virtual or win10:
            space = self.address_space
        else:
            space = self.address_space.physical_space()

        if win10:
            cookie = obj.VolMagic(space).ObHeaderCookie.v()

        # create instances of the various scanners linked
        # to the desired address space 
        scanners = [scanner(space) for scanner in self.scanners]

        # extract the initial pool tags as the list of needles
        needles = dict((scanner.pooltag, scanner) for scanner in scanners)

        # an instance of the multi pool scanner 
        scanner = MultiPoolScanner(needles = [scanner.pooltag for scanner in scanners])

        pool_tag_offset = space.profile.get_obj_offset("_POOL_HEADER", "PoolTag")
    
        for tag, offset in scanner.scan(address_space = space, 
                                   offset = self.start_offset, 
                                   maxlen = self.max_length):

            # a pool header at this offset but native kernel space 
            pool = obj.Object("_POOL_HEADER", 
                              offset = offset - pool_tag_offset, 
                              vm = space, 
                              native_vm = self.address_space)

            # retrieve the scanner object from the tag
            scanobj = needles[tag]

            # pass the pool header to the checks
            if not self._run_all_checks(checks = scanobj.checks,
                                        pool_header = pool):
                continue 

            # we use these approaches per scanner or if the user specifies
            use_top_down = scanobj.use_top_down or self.use_top_down
            skip_type_check = scanobj.skip_type_check or self.show_unalloc

            result = pool.get_object(struct_name = scanobj.struct_name, 
                                     object_type = scanobj.object_type, 
                                     use_top_down = use_top_down, 
                                     skip_type_check = skip_type_check)

            if scanobj.padding > 0:
                result = obj.Object(scanobj.struct_name, 
                                    offset = result.obj_offset + scanobj.padding,
                                    vm = result.obj_vm,
                                    native_vm = result.obj_native_vm)

            # let the object determine if its valid or not 
            if result.is_valid():
                yield result

#--------------------------------------------------------------------------------
# The base pool scanner class
#--------------------------------------------------------------------------------

class PoolScanner(object):
    """A generic pool scanner class"""

    def __init__(self, address_space):
        self.address_space = address_space

        # the name of a structure which exists in the pool (i.e. _EPROCESS)
        self.struct_name = ""

        # an executive object type name (i.e. File, Mutant) 
        self.object_type = ""

        # use the top down approach (otherwise the bottom-up)
        self.use_top_down = False

        # show unallocated objects (0xbad0b0b0)
        self.skip_type_check = False

        # the four-byte ASCII pool tag 
        self.pooltag = None

        # a list of checks to be performed in the supplied order 
        self.checks = []

        # number of bytes between the end of the pool header and 
        # start of the structure contained within. currently only
        # used for atom tables. 
        self.padding = 0 

## The following are checks for pool scanners.

class PoolTagCheck(scan.ScannerCheck):
    """ This scanner checks for the occurance of a pool tag """
    def __init__(self, address_space, tag = None, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.tag = tag

    def skip(self, data, offset):
        try:
            nextval = data.index(self.tag, offset + 1)
            return nextval - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset

    def check(self, offset):
        data = self.address_space.read(offset, len(self.tag))
        return data == self.tag

class CheckPoolType(scan.ScannerCheck):
    """ Check the pool type """
    def __init__(self, address_space, paged = False,
                 non_paged = False, free = False, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.non_paged = non_paged
        self.paged = paged
        self.free = free

    def check(self, offset):
        pool_hdr = obj.Object('_POOL_HEADER', vm = self.address_space,
                             offset = offset - 4)

        return ((self.non_paged and pool_hdr.NonPagedPool) or
               (self.free and pool_hdr.FreePool) or
               (self.paged and pool_hdr.PagedPool))

class CheckPoolSize(scan.ScannerCheck):
    """ Check pool block size """
    def __init__(self, address_space, condition = (lambda x: x == 8), **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.condition = condition

    def check(self, offset):
        pool_hdr = obj.Object('_POOL_HEADER', vm = self.address_space,
                             offset = offset - 4)

        block_size = pool_hdr.BlockSize.v()

        pool_alignment = obj.VolMagic(self.address_space).PoolAlignment.v()

        return self.condition(block_size * pool_alignment)

class SinglePoolScanner(scan.BaseScanner):

    def object_offset(self, found, address_space):
        """ 
        The name of this function "object_offset" can be misleading depending
        on how its used. Even before removing the preambles (r1324), it may not
        always return the offset of an object. Here are the rules:

        If you subclass PoolScanner and do not override this function, it 
        will return the offset of _POOL_HEADER. If you do override this function,
        it should be used to calculate and return the offset of your desired 
        object within the pool. Thus there are two different ways it can be done. 

        Example 1. 

        For an example of subclassing PoolScanner and not overriding this function, 
        see filescan.PoolScanFile. In this case, the plugin (filescan.FileScan) 
        treats the offset returned by this function as the start of _POOL_HEADER 
        and then works out the object from the bottom up: 

            for offset in PoolScanFile().scan(address_space):
                pool_obj = obj.Object("_POOL_HEADER", vm = address_space,
                     offset = offset)
                ##
                ## Work out objects base here
                ## 

        Example 2. 

        For an example of subclassing PoolScanner and overriding this function, 
        see filescan.PoolScanProcess. In this case, the "work" described above is
        done here (in the sublcassed object_offset). Thus in the plugin (filescan.PSScan)
        it can directly instantiate _EPROCESS from the offset we return. 

            for offset in PoolScanProcess().scan(address_space):
                eprocess = obj.Object('_EPROCESS', vm = address_space,
                        native_vm = kernel_as, offset = offset)
        """

        ## Subtract the offset of the PoolTag member to get the start 
        ## of _POOL_HEADER. This is done because PoolScanners search 
        ## for the PoolTag.
        return found - self.buffer.profile.get_obj_offset('_POOL_HEADER', 'PoolTag')

    def scan(self, address_space, offset = 0, maxlen = None):
        for i in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield self.object_offset(i, address_space)
