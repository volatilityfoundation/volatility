# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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

"""
@author:       Andrew Case and Golden G. Richard III
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com / golden@arcanealloy.com
@organization: 
"""

import os
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.mac.common as common
import volatility.plugins.mac.proc_maps as proc_maps
import struct
import WKdm

class mac_dump_maps(proc_maps.mac_proc_maps):
    """ Dumps memory ranges of process(es), optionally including pages in compressed swap """

    def __init__(self, config, *args, **kwargs):         
        proc_maps.mac_proc_maps.__init__(self, config, *args, **kwargs)         
        self._config.add_option('MAP-ADDRESS', short_option = 's', default = None, help = 'Filter by starting address of map', action = 'store', type = 'long') 
        self._config.add_option('OUTPUTFILE', short_option = 'O', default = None, help = 'Output File', action = 'store', type = 'str')
        self._config.add_option('DECOMPRESS-SWAP', default = False, help = 'Also decompress pages in compressed swap', action = 'store_true')
        self._config.add_option('ONLY-DECOMPRESSED-SWAP', default = False, help = 'Dump only successfully decompressed swap pages, nothing else', action = 'store_true')
        self._config.add_option('SKIP-WRITING', short_option = 't',
                                help = 'Skip writing pages, just print stats and optionally test decompression',
                                action = 'store_true', default = False)

        # defined in osfmk/vm/vm_compressor.h; proper decompression relies on these
        self.C_SEG_BUFSIZE =               (1024 * 256)
        self.C_SEG_ALLOCSIZE =             (self.C_SEG_BUFSIZE + 4096)
        self.C_SEG_SLOT_ARRAYS =            6
        self.C_SEG_SLOT_ARRAY_SIZE =       64        
        self.C_SEG_SLOT_ARRAY_MASK =       (self.C_SEG_SLOT_ARRAY_SIZE - 1)
        self.C_SEG_OFFSET_ALIGNMENT_MASK = 0x3

        # defined in osfmk/vm/vm_compressor_pager.c; proper slot lookup relies on these

        self.COMPRESSOR_SLOTS_CHUNK_SIZE = 512
        self.COMPRESSOR_SLOTS_PER_CHUNK  = 128    #   (COMPRESSOR_SLOTS_CHUNK_SIZE / sizeof (compressor_slot_t)), compressor_slot_t is a 32-bit int       

        # WKdm decompression in Python
        self.wkdm=WKdm.WKdm()

        self.dest = [0] * self.wkdm.PAGE_SIZE_IN_WORDS

        self.successful_decompressions = 0

        # don't try to deal with maps larger than this--just skip them
        self.MAXMAPSIZE = 16000000000

    def compressed_page_location(self, outfd, map, addr):
        # return (seg, idx) pair that identifies the location of a
        # compressed page starting at 'addr' and belonging to a
        # vm_map_entry 'map' in the compressor store.  Returns (None,
        # None) if the compressor doesn't own this page.

        # based on compressor_pager_slot_lookup() in osfmk/vm/vm_compressor_pager.c and 
        # c_decompress_page in osfmk/vm_compressor.c

        vm_obj = map.object.vm_object
        if not vm_obj.is_valid() or vm_obj.pager_created == 0 or vm_obj.pager_initialized == 0 or vm_obj.pager_ready == 0:
            # compressor can't own pages from this object--object has no pager or pager isn't initialized
            (seg, idx) = (None, None)
        else:
            #print "PAGING OFFSET: " + str(vm_obj.paging_offset)
            addr += vm_obj.paging_offset
            page_num = addr / self.wkdm.PAGE_SIZE_IN_BYTES
            pager = vm_obj.pager.dereference_as("compressor_pager")
            pager_name = pager.cpgr_pager_ops.memory_object_pager_name.dereference_as("char")
            if pager_name != "c":   # "compressor pager" in pager ops 
                # if the pager isn't the compressor_pager, then move on
                # print "  Corresponding pager " + pager_name + " isn't the compressor pager. Substituting zero page." 
                (seg, idx) = (None, None)
            elif not pager.is_valid():
            # pager isn't initialized 
                outfd.write("  Pager isn't initialized. Substituting zero page.\n")
                (seg, idx) = (None, None)
            # page is out of range
            elif page_num > pager.cpgr_num_slots:
                outfd.write("  page_num > pager.cpgr_num_slots: " + str(page_num) + " " + str(pager.cpgr_num_slots) + ".  Substituting zero page.\n")
                (seg, idx) = (None, None)
            else:
                #print "## " + str(pager.cpgr_num_slots)
                #print "## " + str(self.COMPRESSOR_SLOTS_PER_CHUNK)
                num_chunks = (pager.cpgr_num_slots + self.COMPRESSOR_SLOTS_PER_CHUNK - 1) / self.COMPRESSOR_SLOTS_PER_CHUNK
                if num_chunks > 1:
                    # array of chunks
                    chunk_idx = page_num / self.COMPRESSOR_SLOTS_PER_CHUNK
                    cpgr_islots = obj.Object("Array", offset = pager.cpgr_slots.cpgr_islots, targetType = "Pointer",   
                                            count = num_chunks, vm = self.addr_space)                                  
                    chunks_ptr = cpgr_islots[chunk_idx]
                    if chunks_ptr.is_valid():
                        chunk = obj.Object("Array", offset = chunks_ptr, targetType = "unsigned int",  # compressor_slot_t
                                           count = self.COMPRESSOR_SLOTS_PER_CHUNK, vm = self.addr_space)
                        slot_idx = page_num % self.COMPRESSOR_SLOTS_PER_CHUNK                        

                        # chunk[slot_idx] is actually a c_slot_mapping
                        # struct  c_slot_mapping {
                        #        uint32_t        s_cseg:22,      /* segment number + 1 */
                        #                        s_cindx:10;     /* index in the segment */
                        # };

                        # print "DOUBLE LEVEL SEGIDX bitfield is " + str(chunk[slot_idx])

                        seg = chunk[slot_idx] & 0x3FFFFF
                        idx = chunk[slot_idx] >> 22
                    else:
                        (seg, idx) = (None, None)
                else:
                    slot_idx = page_num;
                    cpgr_dslots = obj.Object("Array", offset = pager.cpgr_slots.cpgr_dslots, targetType = "unsigned int",   # actually compressor_slot_t, == int; 
                                            count = pager.cpgr_num_slots, vm = self.addr_space)                             # unsigned here because we have to 

                    # cpgr_dslots[slot_idx] is actually a c_slot_mapping:
                    # struct  c_slot_mapping {
                    #        uint32_t        s_cseg:22,      /* segment number + 1 */
                    #                        s_cindx:10;     /* index in the segment */
                    # };

                    # print "SINGLE LEVEL SEGIDX bitfield is " + str(cpgr_dslots[slot_idx])
                    
                    seg = cpgr_dslots[slot_idx] & 0x3FFFFF
                    idx = cpgr_dslots[slot_idx] >> 22

        return (seg, idx)                


    def decompress(self, outfd, seg, idx):
        # decompress and return 4K page identified by (seg, idx).  Returns None if decompression fails.
        page = None
        if seg >= self.c_segment_count or seg < 1:
            outfd.write("  Segment out of bounds: " + str(seg) + ". Must be > 0 and < c_segment_count == " + str(self.c_segment_count) + ". Substituting zero page.\n")
        else:
            c_seg = self.c_segments[seg - 1].c_seg          # seg is actually segment index + 1
            if c_seg.c_ondisk == 1:
                outfd.write("  Segment " + str(seg) + " is swapped out. Substituting zero page.\n")
            else:
                j1 = idx / self.C_SEG_SLOT_ARRAY_SIZE
                j2 = idx & self.C_SEG_SLOT_ARRAY_MASK

                cslot_array = c_seg.c_slots[j1]
                if cslot_array.is_valid():
                    cslots = obj.Object("Array", offset = cslot_array, targetType = "c_slot", 
                                        count = self.C_SEG_SLOT_ARRAY_SIZE, vm = self.addr_space)
                    cslot=cslots[j2]
                    (csize, compressed, status) = (4096 / 4, False, "UNCOMPRESSED") if (cslot.c_size == 4095) else (cslot.c_size / 4, True, "COMPRESSED")
                    if csize > 0:
                        outfd.write("  Slot " + str(j1) + ", " + str(j2) + ": offset = " + str(cslot.c_offset * 4) + " bytes, size = " + str(csize * 4) + " bytes, " + status + "\n")
                        page = obj.Object("Array", offset = c_seg.c_store.c_buffer+cslot.c_offset * 4, targetType = "int", 
                                          count = csize, vm = self.addr_space)
                        if compressed:
                            # try to decompress page. Compressed data is fed to WKdm as an array of 32-bit ints.
                            decompressed = self.wkdm.WKdm_decompress(page, self.dest)
                            if decompressed > 0:
                                page = self.dest[:]
                                outfd.write("  Decompression successful.\n")
                            else:
                                outfd.write("  Decompression failed.  Substituting zero page.\n")
                                page = None
                        else:
                            # for uniformity, so len() will work in _read_addr_range()
                            page = page[:]
                            outfd.write("  Decompression successful.\n")

        return page                        

                                
    def render_text(self, outfd, data):
        common.set_plugin_members(self)
        if not self._config.OUTPUTFILE:
            debug.error("Please specify an OUTPUTFILE")
        elif os.path.exists(self._config.OUTPUTFILE):
            debug.error("Cowardly refusing to overwrite an existing file.")
                    
        outfile = open(self._config.OUTPUTFILE, "wb+")
        map_address = self._config.MAP_ADDRESS

        size = 0

        self.table_header(outfd, [("Pid", "8"), 
                          ("Name", "20"),
                          ("Start", "#018x"),
                          ("End", "#018x"),
                          ("Perms", "9"),
                          ("Map Name", "")])

        # from osfmk/vm/vm_object.h.  compressor_object is the high level VM object.
        self.compressor_object = obj.Object("vm_object", 
                                       offset = self.addr_space.profile.get_symbol("_compressor_object_store"), 
                                       vm = self.addr_space)
        
        # from osfmk/vm/vm_compressor.c.  c_segments is an array of c_segu objects, which track and store compressed pages.
        # c_segment_count is current size of c_segments array.
        self.c_segment_count = obj.Object("unsigned int", 
                                          offset = self.addr_space.profile.get_symbol("_c_segment_count"), 
                                          vm = self.addr_space)
        
        self.c_segments_ptr = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("_c_segments"),
                                         vm = self.addr_space)
        
        self.c_segments = obj.Object("Array", targetType = "c_segu", count = self.c_segment_count, 
                                     offset = self.c_segments_ptr, vm = self.addr_space)
        
        for proc, map in data:
            self.table_row(outfd, 
                           str(proc.p_pid), proc.p_comm, 
                           map.links.start, 
                           map.links.end, 
                           map.get_perms(), 
                           map.get_path())

            if (map.links.end - map.links.start) > self.MAXMAPSIZE:
                outfd.write("Skipping suspiciously large map, smearing is suspected.  Adjust MAXMAPSIZE to override.\n")
                continue
            if not map_address or map_address == map.links.start: 
                for page in self._read_addr_range(outfd, proc, map):
                    if not page is None:
                        size += self.wkdm.PAGE_SIZE_IN_BYTES
                        if not self._config.SKIP_WRITING:
                            for k in range(0, self.wkdm.PAGE_SIZE_IN_WORDS):
                                outfile.write(struct.pack('<i', page[k]))
                    
        outfile.close()
        outfd.write("Wrote {0} bytes.\n".format(size))
        if self._config.DECOMPRESS_SWAP:
            outfd.write("{0} pages were successfully decompressed.\n".format(self.successful_decompressions))


    def _read_addr_range(self, outfd, proc, map):
        # read pages from the address space for a map and optionally decompress pages in compressed swap.
        mapstart = map.links.start
        mapoffset = map.offset
        start = map.links.start
        end = map.links.end

        # set the as with our new dtb so we can read from userland
        proc_as = proc.get_process_address_space()

        while start < end:
            rawpage = proc_as.read(start, self.wkdm.PAGE_SIZE_IN_BYTES)
            # need a page-sized buffer of 32-bit words, because the decompressor
            # expects that 

            if isinstance(rawpage, obj.NoneObject) or rawpage is None:
                # NoneObject encapsulates an error from read() on the
                # address space--couldn't read a page, so fail and
                # just substitute a page of zeros, below
                page = None
            else:
                i=0
                page = []
                while i < self.wkdm.PAGE_SIZE_IN_WORDS:
                    (intval,) = struct.unpack('<i', rawpage[i*4:i*4+4])
                    page.append(intval)
                    i += 1
                    
            if not page is None and self._config.ONLY_DECOMPRESSED_SWAP:
                # only decompressed pages--don't yield pages that are present
                page = None
            elif page is None and not self._config.DECOMPRESS_SWAP and not self._config.ONLY_DECOMPRESSED_SWAP:
                # page isn't present and not decompressing swap, which is the only other
                # potential source of data for the page
                page = [0] * self.wkdm.PAGE_SIZE_IN_WORDS
            elif page is None:
                # see if the page is in compressed swap--if so, decompress; otherwise,
                # return a zero page like as.zread().  The location of the page in
                # compressed swap is represented by a (seg,idx) tuple.  The address
                # must be an offset from the beginning of the map
                (seg, idx) = self.compressed_page_location(outfd, map, start - mapstart + mapoffset)
                if seg is None or seg == 0:
                    # page isn't owned by compressor
                    if self._config.ONLY_DECOMPRESSED_SWAP:
                        # don't yield anything for pages that can't be decompressed if only dumping
                        # decompressed swap
                        page = None
                    else:
                        page = [0] * self.wkdm.PAGE_SIZE_IN_WORDS
                else:
                    outfd.write("Trying to decompress page for address " + hex(start).rstrip("L") + " with segment, idx: " + str(seg) + ", " + str(idx) + "\n")
                    page = self.decompress(outfd, seg, idx)
                    if page is None:
                        # decompression failed
                        if self._config.ONLY_DECOMPRESSED_SWAP:
                            # don't yield anything for pages that can't be decompressed
                            page = None
                        else:
                            page = [0] * self.wkdm.PAGE_SIZE_IN_WORDS
                    else:
                        self.successful_decompressions += 1
            
            if not page is None:
                # ugly, but don't try to pad pages deliberately set to None
                pagelen = len(page)
                if pagelen != self.wkdm.PAGE_SIZE_IN_WORDS:
                    outfd.write("Page is wrong size: " + str(pagelen) + ". Extending to " + str(self.wkdm.PAGE_SIZE_IN_BYTES) + ".\n")
                    page.extend([0] * (self.wkdm.PAGE_SIZE_IN_WORDS - pagelen))

            yield page
            start = start + self.wkdm.PAGE_SIZE_IN_BYTES


