# Volatility
# Copyright (C) 2007-2019 Volatility Foundation
#
# Authors:
# Blaine Stancill <blaine.stancill@FireEye.com>
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

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.addrspaces.amd64 as amd64
import volatility.plugins.addrspaces.intel as intel
import volatility.win32 as win32

PAGE_SIZE = 0x1000
PAGE_MASK = PAGE_SIZE - 1
XPRESS_ALGO = 3
INVALIDPTEMASK = 0x2000


###############################################################################
# Handles all Win10 memory decompression
###############################################################################
class WindowsMemoryCompression(object):
    """Handles compressed pages on Windows 10."""

    def __init__(self, addrspace, sm_globals, page_file_number):
        self.addrspace = addrspace

        self.sm_globals = obj.Object("_SM_GLOBALS", offset = sm_globals,
                                     vm = self.addrspace)

        self.page_file_number = page_file_number

        self._store_tree_root = self.sm_globals.SmkmStoreMgr.KeyToStoreTree

        self._smkm = self.sm_globals.SmkmStoreMgr.Smkm

        # Simplex caching scheme
        self._page_cache = {}
        self._page_data_cache = {}

        # Store data about the type of OS and architecture
        self._size_of_pointer = self.addrspace.profile.get_obj_size("address")
        self._build_id = self.addrspace.profile.metadata.get('build', 0)
        self._mem_type = self.addrspace.profile.metadata.get('memory_model',
                                                             '32bit')
        # Value to shift PTE to retrieve page file low. The bit position
        # changed around 1803 from bit positions 1-4 to 12-16.
        if self._build_id >= 17134:
            self._pfl_shift = 12
        else:
            self._pfl_shift = 1

    def get_pte(self, vaddr, addrspace):
        '''
        We do this manually rather than at the AS level because the AS we are
        dealing with will not have an entry present for VAs that are in a
        compressed pages.
        '''
        vaddr = long(vaddr)
        pml4e = None
        pdpe = None

        if (not addrspace.pae
                and addrspace.profile.metadata.get(
                    'memory_model', '32bit') == '32bit'):
            pgd = addrspace.get_pgd(vaddr)
        else:
            if addrspace.profile.metadata.get('memory_model',
                                              '32bit') == '32bit':
                pdpe = addrspace.get_pdpi(vaddr)
            else:
                pml4e = addrspace.get_pml4e(vaddr)
                if not addrspace.entry_present(pml4e):
                    return None

                pdpe = addrspace.get_pdpi(vaddr, pml4e)

            if not addrspace.entry_present(pdpe):
                return None

            # Quit early if it is a large page
            if addrspace.page_size_flag(pdpe):
                return None

            pgd = addrspace.get_pgd(vaddr, pdpe)

        if addrspace.entry_present(pgd):

            # Continue if it is not a large page
            if not addrspace.page_size_flag(pgd):
                pte = addrspace.get_pte(vaddr, pgd)

                if pml4e:
                    debug.debug("pml4e: {0:#x}".format(pml4e))
                if pdpe:
                    debug.debug("pdpe: {0:#x}".format(pdpe))
                debug.debug("pgd: {0:#x}".format(pgd))
                debug.debug("pte: {0:#x}".format(pte))

                return pte

        return None

    def is_vaddr_present(self, vaddr, addrspace):
        pte = self.get_pte(vaddr, addrspace)
        if pte:
            return addrspace.entry_present(pte), pte

        return False, None

    def get_page_key(self, vaddr):
        is_present, pte = self.is_vaddr_present(vaddr, self.addrspace)

        if is_present or not pte:
            return None

        # Calculate the page key based on the page file number
        page_file_number = (pte >> self._pfl_shift) & 0x0F
        if page_file_number == self.page_file_number:
            if self._build_id >= 17134:
                # Check if the SwizzleBit is set
                if pte & (1 << 4):
                    return (page_file_number << 28) | (pte >> 32)
                else:
                    # Flip bit using InvalidPteMask from MiState.Hardware
                    return (page_file_number << 28) | (
                                (pte >> 32) & ~INVALIDPTEMASK)
            else:
                return (page_file_number << 28) | (pte >> 32)

        return None

    def bisect_right(self, root, key):
        """Custom bisect right to avoid list copies"""
        lo = 0
        hi = root.Elements

        while lo < hi:
            mid = (lo + hi) // 2
            if key < root.Nodes[mid].Key.v():
                hi = mid
            else:
                lo = mid + 1
        return lo

    def b_tree_search(self, root, key):
        if not root:
            return None

        debug.debug("Root: {0:#x}, Key: {1:#x}".format(root, key))

        leaf = bool(root.Leaf.v())
        debug.debug("\tLeaf? {0}".format(leaf))

        # Need to cast as leaf child nodes can be a different size
        if leaf:
            root = root.cast("_B_TREE_LEAF")

        index = self.bisect_right(root, key)
        debug.debug("\tNode Index: {0:#x}".format(index))

        if index:
            node = root.Nodes[index - 1]
            debug.debug("\tNode: {0:#x}".format(node))

            if not leaf:
                return self.b_tree_search(node.Child.dereference(), key)

            # Correct key found from leaf
            debug.debug("\tNode Key: {0:#x}".format(node.Key.v()))
            if node.Key.v() == key:
                debug.debug("\tNode Value: {0:#x}".format(node.Value.v()))
                return node.Value.v()

            # Worst case, no key found and we're at a leaf
            return None
        else:
            # If it's less than all the keys, use the root's left-most child
            return self.b_tree_search(root.LeftChild.dereference(), key)

    def get_smkm_store_index(self, page_key):
        index = self.b_tree_search(self._store_tree_root, page_key)

        if not index:
            raise KeyError("Could not find Smkm store index for "
                           "page key: {0:#x}".format(page_key))

        if (index >> 24) & 0xFF == 1:
            raise KeyError("Smkm store index is not valid for "
                           "page key: {0:#x}".format(page_key))

        return index & 0x3FF

    def get_smkm_store(self, smkm_store_index):
        meta_index = smkm_store_index >> 5
        smkm_meta_ptr = self._smkm.StoreMetaDataPtrArray[meta_index]

        store_index = smkm_store_index & 0x1F
        smkm_meta = smkm_meta_ptr.dereference()[store_index]

        debug.debug("Smkm Metadata: {0:#x}".format(smkm_meta))
        debug.debug("Smkm Store: {0:#x}".format(smkm_meta.SmkmStore))
        return smkm_meta.SmkmStore

    def get_region_key(self, smkm_store, page_key):
        st_data_mgr = smkm_store.StStore.StDataMgr
        debug.debug("StDataMgr: {0:#x}".format(st_data_mgr))

        root = st_data_mgr.PagesTree
        debug.debug("Pages Tree: {0:#x}".format(root))

        region_key = self.b_tree_search(root, page_key)
        if not region_key:
            raise KeyError("Could not find region key for "
                           "page key: {0:#x}".format(page_key))

        debug.debug("Region Key: {0:#x}".format(region_key))
        return region_key

    def get_page_record(self, smkm_store, region_key):
        chunk_metadata = smkm_store.StStore.StDataMgr.ChunkMetaData
        debug.debug("Chunk Metadata: {0:#x}".format(chunk_metadata))

        # Get the encoded metadata about the chunk
        encoded_metadata = region_key >> (chunk_metadata.BitValue.v() & 0xFF)
        debug.debug("Encoded Metadata: {0:#x}".format(encoded_metadata))

        # Highest non-zero bit position of encoded_metadata is the index into
        # an array of pointers where each pointer points to an array of chunks
        ptr_index = int(encoded_metadata).bit_length() - 1
        debug.debug("Chunk Ptr Index: {0:#x}".format(ptr_index))

        chunk_array = chunk_metadata.ChunkPtrArray[ptr_index]
        debug.debug("Chunk Array: {0:#x}".format(chunk_array))

        # Flip the highest bit to get an index into the chunk array
        chunk_array_index = ((1 << (ptr_index & 0xFF)) ^ encoded_metadata)
        debug.debug("Chunk Array Index: {0:#x}".format(chunk_array_index))

        # Treat chunk size differently based on OS type and architecture
        if self._build_id >= 15063 and self._mem_type == '32bit':
            chunk_size = 3 * self._size_of_pointer
        else:
            chunk_size = 2 * self._size_of_pointer

        debug.debug("Chunk Size: {0:#x}".format(chunk_size))

        # Get the chunk from the chunk array
        chunk_offset = chunk_array + (chunk_array_index * chunk_size)
        debug.debug("Chunk Offset: {0:#x}".format(chunk_offset))

        # The first field in the chunk points to the chunk's page record data
        page_record_ptr = obj.Object("Pointer",
                                     offset = chunk_offset,
                                     vm = self.addrspace)
        debug.debug("Page Record Ptr: {0:#x}".format(page_record_ptr))

        # Page record data begins with a header followed by a page record array
        page_record_array = (page_record_ptr +
                             chunk_metadata.ChunkPageHeaderSize.v())
        debug.debug("Page Record Array: {0:#x}".format(page_record_array))

        # Calculate page record index based on page record size
        page_record_index = (((region_key &
                               chunk_metadata.PageRecordsPerChunkMask.v()) *
                              chunk_metadata.PageRecordSize.v()) & 0xFFFFFFFF)
        debug.debug("Page Record Index: {0:#x}".format(page_record_index))

        # Get the page record from the page record array
        page_record_offset = page_record_array + page_record_index
        debug.debug("Page Record Offset: {0:#x}".format(page_record_offset))

        # Cast to our defined type
        st_page_record = obj.Object("_ST_PAGE_RECORD",
                                    offset = page_record_offset,
                                    vm = self.addrspace)
        debug.debug("StPage Record: {0:#x}".format(st_page_record))

        # If page record is not valid, follow next record
        if st_page_record.Key.v() == 0xFFFFFFFF:
            return self.get_page_record(smkm_store, st_page_record.NextKey.v())

        return st_page_record

    def get_page_address(self, smkm_store, page_record):
        st_data_mgr = smkm_store.StStore.StDataMgr

        # Calculate encoded region array index
        key = page_record.Key.v()
        debug.debug("Record Key: {0:#x}".format(key))

        region_index = (key >> (st_data_mgr.RegionIndexMask.v() & 0xFF))
        debug.debug("Region Index: {0:#x}".format(region_index))

        # Get a pointer to the region
        region_index *= self._size_of_pointer
        debug.debug("Region Index x sizeof(ptr): {0:#x}".format(region_index))

        region_offset = smkm_store.CompressedRegionPtrArray.v() + region_index
        debug.debug("Region Offset: {0:#x}".format(region_offset))

        region_ptr = obj.Object("Pointer",
                                offset = region_offset,
                                vm = self.addrspace)

        # Align the base
        if self._mem_type == '32bit':
            region_ptr &= 0x7FFF0000
        else:
            region_ptr &= 0x7FFFFFFFFFFF0000
        debug.debug("Region Base: {0:#x}".format(region_ptr))

        # Calculate encoded offset to the compressed page address in the region
        page_offset = (key & st_data_mgr.RegionSizeMask.v()) << 4
        debug.debug("Page Offset: {0:#x}".format(page_offset))

        # Get the address of the compressed page
        page_address = region_ptr + page_offset
        debug.debug("Resolved Page Addr: {0:#x}".format(page_address))

        return page_address

    def get_page_data_cache(self, page_key):
        if page_key not in self._page_data_cache:
            page_record, proc_space, page_addr = self.get_page_cache(page_key)

            # Cache failure if the compressed page is not available
            if not page_record:
                self._page_data_cache[page_key] = None
                return None

            # If the compressed size is the size of a page, return as is
            comp_size = page_record.CompressedSize.v()
            if comp_size == PAGE_SIZE:
                comp_data = proc_space.read(page_addr, comp_size)
                self._page_data_cache[page_key] = comp_data
                return comp_data

            # Mask the size to get the actual compressed size
            comp_size &= PAGE_MASK

            # Read in only what is needed
            comp_data = proc_space.read(page_addr, comp_size)
            if not comp_data:
                self._page_data_cache[page_key] = None
                return None

            try:
                decompressed_data = win32.xpress.xpress_decode(comp_data)
            except Exception as e:
                debug.debug("Error decompressing: {0}".format(str(e)))
                self._page_data_cache[page_key] = None
                return None

            len_decompressed = len(decompressed_data)
            if len_decompressed != PAGE_SIZE:
                debug.debug("Decompressed data is not the "
                            "size of a page: {0:#x}".format(len_decompressed))
                self._page_data_cache[page_key] = None
                return None

            # Cache the decompressed page data
            self._page_data_cache[page_key] = decompressed_data

        return self._page_data_cache[page_key]

    def get_page_cache(self, page_key):
        if page_key not in self._page_cache:
            debug.debug("Page Key: {0:#x}".format(page_key))

            try:
                smkm_store_index = self.get_smkm_store_index(page_key)
                debug.debug("Smkm Store Index: {0}".format(smkm_store_index))
            except KeyError as e:
                debug.debug("Tree Error: {0}".format(str(e)))
                self._page_cache[page_key] = (None, None, None)
                return None, None, None

            smkm_store = self.get_smkm_store(smkm_store_index)

            # Stop early if it's a non-supported compression algorithm
            comp_algo = smkm_store.StStore.StDataMgr.CompressionAlgorithm.v()
            if comp_algo != XPRESS_ALGO:
                debug.debug("Unsupported decompression "
                            "algorithm: {0}".format(comp_algo))
                return None, None, None

            # Walk the data-structures to get the compressed page address
            try:
                region_key = self.get_region_key(smkm_store, page_key)
            except KeyError as e:
                debug.debug("Tree Error: {0}".format(str(e)))
                self._page_cache[page_key] = (None, None, None)
                return None, None, None

            page_record = self.get_page_record(smkm_store, region_key)
            page_addr = self.get_page_address(smkm_store, page_record)

            # Check if the address is valid in the context of it's owner
            debug.debug("Owner Process: {0:#x} -> {1}".format(
                smkm_store.OwnerProcess.UniqueProcessId,
                smkm_store.OwnerProcess.ImageFileName))
            proc_space = smkm_store.OwnerProcess.get_process_address_space()
            comp_data_is_present, pte = self.is_vaddr_present(page_addr,
                                                              proc_space)

            # If not present, the compressed page may be paged to disk
            if not comp_data_is_present:
                debug.debug("Compressed data is likely paged out")
                self._page_cache[page_key] = (None, None, None)
                return None, None, None

            self._page_cache[page_key] = (page_record, proc_space, page_addr)

        return self._page_cache[page_key]

    def get_compressed_page_paddr(self, vaddr):
        debug.debug("Target Addr: {0:#x}".format(vaddr))

        page_key = self.get_page_key(vaddr)
        if page_key:
            _, proc_space, page_addr = self.get_page_cache(page_key)
            if proc_space:
                return proc_space.vtop(page_addr)

        return None

    def decompress_page_data(self, vaddr, offset, length):
        debug.debug("Target Addr: {0:#x}".format(vaddr))

        page_key = self.get_page_key(vaddr)
        if page_key:
            page_data = self.get_page_data_cache(page_key)
            if page_data:
                return page_data[offset:offset + length]

        return None


###############################################################################
# Address spaces to transparently deal with Win10 memory
###############################################################################
class Win10CompressedPagedMemory(object):
    def __init__(self, paged_as, memcompress):
        # Initialize a local copy of the paged address space to use
        self.paged_as = paged_as

        # Object to decompress Windows 10 compressed memory
        self.memcompress = memcompress

    @property
    def sm_globals(self):
        # May raise an exception which causes the AS to fail loading
        if not hasattr(self, "_sm_globals"):
            sm_globals = obj.VolMagic(self.paged_as).SmGlobals.v()

            if not sm_globals:
                raise Exception("Invalid nt!SmGlobals value")

            self._sm_globals = sm_globals

        return self._sm_globals

    @property
    def page_file_number(self):
        if not hasattr(self, "_page_file_number"):
            page_file_number = obj.VolMagic(self.paged_as).VSPageFileNumber.v()

            if not page_file_number:
                raise Exception("Invalid Virtual Store page file number value")

            self._page_file_number = page_file_number

        return self._page_file_number

    @property
    def pfl_shift(self):
        '''
        Value to shift PTE to retrieve page file low. The bit position changed
        around 1803 from 1-4 to 12-16.
        '''
        if not hasattr(self, "_pfl_shift"):
            build = self.profile.metadata.get('build', 14393)

            if build >= 17134:
                self._pfl_shift = 12
            else:
                self._pfl_shift = 1

        return self._pfl_shift

    def is_valid_profile(self, profile):
        '''
        This address space should only be used with recent Win 10 profiles
        '''
        valid = self.paged_as.is_valid_profile(profile)
        os = profile.metadata.get('os', '')
        major = profile.metadata.get('major', 0)
        minor = profile.metadata.get('minor', 0)
        build = profile.metadata.get('build', 0)
        return (valid
                and major >= 6
                and minor >= 4
                and os == 'windows'
                and build in [14393, 15063, 16299, 17134, 17763, 18362])

    def entry_present(self, entry):
        present = self.paged_as.entry_present(entry)
        in_virtual_store = self.entry_in_virtual_store(entry, present)
        return present or in_virtual_store

    def entry_in_virtual_store(self, entry, present = None):
        if not present:
            present = self.paged_as.entry_present(entry)

        return (not present and (
            # In virtual store
            (((entry >> self.pfl_shift) & 0x0F) == self.page_file_number) and
            # Not prototype
            not (entry & (1 << 10)) and
            # Not VAD
            not ((entry >> 32) == 0xFFFFFFFF) and
            # Not demand zero
            not ((entry >> 32) == 0)
        ))

    def is_vaddr_compressed(self, vaddr):
        paddr = self.paged_as.vtop(vaddr)

        if not paddr:
            pte = self.memcompress.get_pte(vaddr, self.paged_as)
            if pte:
                return self.entry_in_virtual_store(pte)

        return False

    def vtop(self, vaddr):
        # If the virual address already maps to a physical address, return it
        paddr = self.paged_as.vtop(vaddr)

        # Attempt to return a physical address for compressed pages.
        # Mainly to allow plugins to work if using vtop() to check if
        # an address is valid.
        if not paddr:
            if self.is_vaddr_compressed(vaddr):
                paddr = self.memcompress.get_compressed_page_paddr(vaddr)

        return paddr

    def _partial_read(self, vaddr, length):
        # The offset within the page where we start reading
        page_offset = vaddr & PAGE_MASK

        # How much data can we satisfy?
        available = min(PAGE_SIZE - page_offset, length)

        if self.is_vaddr_compressed(vaddr):
            return self.memcompress.decompress_page_data(vaddr, page_offset,
                                                         available)
        else:
            return self.paged_as.read(vaddr, available)

    def read(self, addr, length, zread = False):
        result = ''

        while length > 0:
            buf = self._partial_read(addr, length)
            if not buf:
                break

            addr += len(buf)
            length -= len(buf)
            result += buf

        if result == '':
            if zread:
                return '\0' * length

            result = obj.NoneObject("Unable to read data at {0:#x} "
                                    "for length {1:#x}".format(addr, length))
        else:
            if zread:
                result += ('\0' * length)

        return result

    def zread(self, addr, length):
        return self.read(addr, length, zread = True)


class Win10CompressedAMD64PagedMemory(Win10CompressedPagedMemory,
                                      amd64.SkipDuplicatesAMD64PagedMemory):
    order = 50

    def __init__(self, base, config, *args, **kwargs):
        # We must be stacked on someone else
        self.as_assert(base, "No base Address Space")

        # Initialize a local copy of the paged address space to use
        self.paged_as = amd64.SkipDuplicatesAMD64PagedMemory(base, config,
                                                             *args, **kwargs)

        if obj.VolMagic(self.paged_as).DisableWin10MemCompress.v():
            raise Exception("Disabling Win10 memory decompression AS")

        # Object to decompress Windows 10 compressed memory
        self.memcompress = WindowsMemoryCompression(
            addrspace = self.paged_as,
            sm_globals = self.sm_globals,
            page_file_number = self.page_file_number)

        # Initialize our memory compression parent address space
        Win10CompressedPagedMemory.__init__(self, paged_as = self.paged_as,
                                            memcompress = self.memcompress)

        # Initialize our paged parent address space
        amd64.SkipDuplicatesAMD64PagedMemory.__init__(self, base, config,
                                                      *args, **kwargs)


class Win10CompressedIA32PagedMemory(Win10CompressedPagedMemory,
                                     intel.IA32PagedMemory):
    order = 55

    def __init__(self, base, config, *args, **kwargs):
        # We must be stacked on someone else
        self.as_assert(base, "No base Address Space")

        # Initialize a local copy of the paged address space to use
        self.paged_as = intel.IA32PagedMemory(base, config, *args, **kwargs)

        if obj.VolMagic(self.paged_as).DisableWin10MemCompress.v():
            raise Exception("Disabling Win10 memory decompression AS")

        # Object to decompress Windows 10 compressed memory
        self.memcompress = WindowsMemoryCompression(
            addrspace = self.paged_as,
            sm_globals = self.sm_globals,
            page_file_number = self.page_file_number)

        # Initialize our memory compression parent address space
        Win10CompressedPagedMemory.__init__(self, paged_as = self.paged_as,
                                            memcompress = self.memcompress)

        # Initialize our parent address space
        intel.IA32PagedMemory.__init__(self, base, config, *args, **kwargs)


class Win10CompressedIA32PagedMemoryPae(Win10CompressedPagedMemory,
                                        intel.IA32PagedMemoryPae):
    order = 50

    def __init__(self, base, config, *args, **kwargs):
        # We must be stacked on someone else
        self.as_assert(base, "No base Address Space")

        # Initialize a local copy of the paged address space to use
        self.paged_as = intel.IA32PagedMemoryPae(base, config, *args, **kwargs)

        if obj.VolMagic(self.paged_as).DisableWin10MemCompress.v():
            raise Exception("Disabling Win10 memory decompression AS")

        # Object to decompress Windows 10 compressed memory
        self.memcompress = WindowsMemoryCompression(
            addrspace = self.paged_as,
            sm_globals = self.sm_globals,
            page_file_number = self.page_file_number)

        # Initialize our memory compression parent address space
        Win10CompressedPagedMemory.__init__(self, paged_as = self.paged_as,
                                            memcompress = self.memcompress)

        # Initialize our parent address space
        intel.IA32PagedMemoryPae.__init__(self, base, config, *args, **kwargs)
