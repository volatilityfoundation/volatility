# Volatility
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

"""
@author:       SLAB: Joe Sylve; SLUB and SLOB: Fulvio Di Girolamo, Angelo Russi
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

MAX_NODES = 1024
PAGE_SIZE = 4096

class kmem_cache(obj.CType):
    def get_type(self):
        raise NotImplementedError

    def get_name(self):
        return str(self.name.dereference_as("String", length = 255))

class kmem_cache_slab(kmem_cache):
    def get_type(self):
        return "slab"

    # volatility does not support indexing pointers
    # and the definition of nodelists changes from array to pointer
    def _get_nodelist(self):
        ent = self.nodelists

        if type(ent) == obj.Pointer:
            ret = obj.Object("kmem_list3", offset = ent.dereference(), vm = self.obj_vm)

        elif type(ent) == obj.Array:
            ret = ent[0]
        else:
            debug.error("Unknown nodelists types. %s" % type(ent))

        return ret

    def _get_free_list(self):

        slablist = self._get_nodelist().slabs_free

        for slab in slablist.list_of_type("slab", "list"):
            yield slab

    def _get_partial_list(self):
        slablist = self._get_nodelist().slabs_partial

        for slab in slablist.list_of_type("slab", "list"):
            yield slab

    def _get_full_list(self):
        slablist = self._get_nodelist().slabs_full

        for slab in slablist.list_of_type("slab", "list"):
            yield slab

    def _get_object(self, offset):
        return obj.Object(self.struct_type,
                            offset = offset,
                            vm = self.obj_vm,
                            parent = self.obj_parent,
                            name = self.struct_type)
    def __iter__(self):

        if not self.unalloc:
            for slab in self._get_full_list():
                for i in range(self.num):
                    yield self._get_object(slab.s_mem.v() + i * self.buffer_size)

        for slab in self._get_partial_list():
            if not self.num or self.num == 0:
                return                

            bufctl = obj.Object("Array",
                        offset = slab.v() + slab.size(),
                        vm = self.obj_vm,
                        parent = self.obj_parent,
                        targetType = "unsigned int",
                        count = self.num)

            unallocated = [0] * self.num

            i = slab.free
            while i != 0xFFFFFFFF:
                if i >= self.num:
                    break
                unallocated[i] = 1
                i = bufctl[i]

            for i in range(0, self.num):
                if unallocated[i] == self.unalloc:
                    yield self._get_object(slab.s_mem.v() + i * self.buffer_size)

        if self.unalloc:
            for slab in self._get_free_list():
                for i in range(self.num):
                    yield self._get_object(slab.s_mem.v() + i * self.buffer_size)

class kmem_cache_slub(kmem_cache):

    def get_type(self):
        return "slub"

    def get_size(self):
        return int(self.size())

class kmem_cache_slob():

    def get_type(self):
        return "slob"

class LinuxKmemCacheOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses'] # , 'LinuxVTypes']

    def modification(self, profile):

        if profile.get_symbol("cache_chain"):
            profile.object_classes.update({'kmem_cache': kmem_cache_slab})
        elif profile.get_symbol("slab_caches"):
            profile.object_classes.update({'kmem_cache': kmem_cache_slub})

class linux_slabinfo(linux_common.AbstractLinuxCommand):
    """Mimics /proc/slabinfo on a running machine"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PAGE_SIZE', short_option = 'p', default = 0x1000,
                          help = '<SLOB ONLY>The page size of the analyzed system',
                          action = 'store', type = 'int')
        self._config.add_option('DUMP_FREE_LIST', short_option = 'L', default = None,
                          help = '<SLOB ONLY>Select the free list to dump: (s)mall, (m)edium, (l)arge or (a)ll',
                          action = 'store', type = 'str')
        self._config.add_option('DUMP_FILE', short_option = 'D', default = None, 
                          help = '<SLOB ONLY>When using -L specify the name of the dump file')

    def get_all_kmem_caches(self):
        linux_common.set_plugin_members(self)
        cache_chain = self.addr_space.profile.get_symbol("cache_chain")
        slab_caches = self.addr_space.profile.get_symbol("slab_caches")
        slob_list = self.addr_space.profile.get_symbol("free_slob_small")

        if cache_chain: #slab
            caches = obj.Object("list_head", offset = cache_chain, vm = self.addr_space)
            listm = "next"
            ret = [cache for cache in caches.list_of_type("kmem_cache", listm)]
        elif slob_list : #slob
            slob = kmem_cache_slob()
            ret = [slob]
        else: # slub
            caches = obj.Object("list_head", offset = slab_caches, vm = self.addr_space)
            listm = "list"
            ret = [cache for cache in caches.list_of_type("kmem_cache", listm)]
            
        return ret

    def get_kmem_cache(self, cache_name, unalloc, struct_name = ""):

        if struct_name == "":
            struct_name = cache_name

        for cache in self.get_all_kmem_caches():
            if cache.get_name() == cache_name:
	        cache.newattr("unalloc", unalloc)
                cache.newattr("struct_type", struct_name)
                return cache

        debug.debug("Invalid kmem_cache: {0}".format(cache_name))
        return []

    def calculate(self):
        linux_common.set_plugin_members(self)

        for cache in self.get_all_kmem_caches():
                if cache.get_type() == "slab":
                    active_objs = 0
                    active_slabs = 0
                    num_slabs = 0
                    # shared_avail = 0

                    for slab in cache._get_full_list():
                        active_objs += cache.num
                        active_slabs += 1

                    for slab in cache._get_partial_list():
                        active_objs += slab.inuse
                        active_slabs += 1

                    for slab in cache._get_free_list():
                        num_slabs += 1

                    num_slabs += active_slabs
                    num_objs = num_slabs * cache.num

                    yield [cache.get_name(),
                            active_objs,
                            num_objs,
                            cache.buffer_size,
                            cache.num,
                            1 << cache.gfporder,
                            active_slabs,
                            num_slabs]

                elif cache.get_type() == "slub":
                    active_objs = 0
                    active_slabs = 0
                    num_slabs = 0
                    num_objs = 0
                    objperslabs = 0
                    pagesperslab = 0
                    object_size = 0
                    metadata = 0
                    node = cache.m('node')
                    object_size = cache.m("size")
                    cache_node = obj.Object('kmem_cache_node', offset = node[0], vm = self.addr_space)  
                    page = obj.Object('page', offset = cache_node.partial.m("next"), vm = self.addr_space)
                    ptr = page.freelist.dereference_as("Pointer")
                    if ptr.is_valid() == False:
                        active_objs = "?"
                    else:
                        active_objs = page.counters
                    num_objs = cache_node.total_objects.counter
                    active_slabs = cache_node.nr_slabs.counter
                    num_slabs = cache_node.nr_slabs.counter

                    order = cache.oo.x >> 16
                    pagesperslab = 2**order
                    objperslab = cache.oo.x ^ ((cache.oo.x >>16) << 16)

                    yield [cache.get_name(),
                            active_objs,
                            num_objs,
                            object_size,
                            objperslab,
                            pagesperslab,
                            active_slabs,
                            num_slabs]
                
                else: # slob

                    free_slob_small = self.addr_space.profile.get_symbol("free_slob_small")
                    free_slob_medium = self.addr_space.profile.get_symbol("free_slob_medium")
                    free_slob_large = self.addr_space.profile.get_symbol("free_slob_large")
                    SLOB_BREAK1 = 256
                    SLOB_BREAK2 = 1024

                    # Set the size of a slob unit in bytes depending on the page size
                    page_size = self._config.PAGE_SIZE
                    dump_list = self._config.DUMP_FREE_LIST
                    dump_file = self._config.DUMP_FILE
                    #page_list = None
                    if page_size <= 32767 * 2:
                        slob_unit_size = 2
                        size_type = "short"
                    else:
                        slob_unit_size = 4
                    # Assuming that sizeof(int) = 4...
                        size_type = "int"                    

                    # Create the list_head objects
                    slob_small = obj.Object("list_head", offset = free_slob_small, vm = self.addr_space)
                    slob_medium = obj.Object("list_head", offset = free_slob_medium, vm = self.addr_space)
                    slob_large = obj.Object("list_head", offset = free_slob_large, vm = self.addr_space)

                    # Gather the pages on the lists
                    small_pages = [slob for slob in slob_small.list_of_type("page", "slab_list")]
                    medium_pages = [slob for slob in slob_medium.list_of_type("page", "slab_list")]
                    large_pages = [slob for slob in slob_large.list_of_type("page", "slab_list")]

                    #if(dump_list == 's'):
                    #    page_list = small_pages
                    #elif(dump_list == 'm'):
                    #    page_list = medium_pages
                    #elif(dump_list == 'l'):
                    #    page_list = large_pages
                    #if(page_list != None):
                    #    for page in page_list:
                    #        free_block_addr = page.freelist
                    #        computed_size = 0
                    #        while free_block_addr != 0x0 and computed_size < page.units:
                    #            size_or_off = obj.Object(size_type, offset = free_block_addr, vm = self.addr_space)
                    #            if size_or_off > 0:
                    #                size = size_or_off
                    #                off = obj.Object(size_type, offset = free_block_addr + slob_unit_size, vm = self.addr_space)
                                    # print(off)
                    #                block = self.addr_space.read(free_block_addr, size * slob_unit_size)
                                    #for i in range(size * slob_unit_size / 4):
                                    #    o = obj.Object('int', offset = free_block_addr + slob_unit_size + i * 4, vm = self.addr_space)
                                        # print(self.addr_space)
                                        # print(size)
                                        # print(free_block_addr + slob_unit_size + i)
                                    #print(block)
                    #            else:
                    #                size = 1
                    #                off = -size_or_off
                    #            computed_size += size
                    #            free_block_addr = free_block_addr - free_block_addr % page_size + off * 2

                    if dump_list != None:
                        if dump_file != None:
                            dump = open(dump_file, "wb")
                    
                    # Enumerate the content of free_slob_small
                    range_counters = [0] * 4
                    free_space = 0
                    space_counter = 0
                    for page in small_pages:
                        free_block_addr = page.freelist
                        computed_size = 0
                        while free_block_addr != 0x0 and computed_size < page.units:
                            size_or_off = obj.Object(size_type, offset = free_block_addr, vm = self.addr_space)
                            if size_or_off > 0:
                                size = size_or_off
                                off = obj.Object(size_type, offset = free_block_addr + slob_unit_size, vm = self.addr_space)
                                if (dump_list == "s" or dump_list == "a") and dump_file != None and size * slob_unit_size < SLOB_BREAK1:
                                    block = self.addr_space.read(free_block_addr, size * slob_unit_size)
                                    header = 'Address: ' + hex(free_block_addr) + ', Size: ' + str(size * slob_unit_size) + '\n'
                                    header = header.encode('ascii')
                                    dump.write(header)
                                    dump.write(block)
                                    dump.write(b'\n')
                            else:
                                size = 1
                                off = -size_or_off
                            computed_size += size
                            free_block_addr = free_block_addr - free_block_addr % page_size + off * 2
                            if size >= 256/slob_unit_size:
                                continue
                            free_space += size*slob_unit_size
                            space_counter += 1
                            range_counters[size/(64/slob_unit_size)] += 1
                    yield("free_slob_small", "0-63", range_counters[0])
                    yield("free_slob_small", "64-127", range_counters[1])
                    yield("free_slob_small", "128-191", range_counters[2])
                    yield("free_slob_small", "192-255", range_counters[3])
                    print("------------ slob small stats -----------------")
                    print("free space "+str(free_space)+" | free_mean_size "+str(free_space/space_counter)+" | PAGES "+str(len(small_pages)))
                    print("-------------------- --------------- ----------")

                    # Enumerate the content of free_slob_medium
                    range_counters = [0] * 4
                    free_space = 0
                    space_counter = 0
                    for page in medium_pages:
                        free_block_addr = page.freelist
                        computed_size = 0
                        while free_block_addr != 0x0 and computed_size < page.units:
                            size_or_off = obj.Object(size_type, offset = free_block_addr, vm = self.addr_space)
                            if size_or_off > 0:
                                size = size_or_off
                                off = obj.Object(size_type, offset = free_block_addr + slob_unit_size, vm = self.addr_space)
                                if (dump_list == "m" or dump_list == "a") and dump_file != None and size * slob_unit_size >= SLOB_BREAK1 and size * slob_unit_size < SLOB_BREAK2:
                                    block = self.addr_space.read(free_block_addr, size * slob_unit_size)
                                    header = 'Address: ' + hex(free_block_addr) + ', Size: ' + str(size * slob_unit_size) + '\n'
                                    header = header.encode('ascii')
                                    dump.write(header)
                                    dump.write(block)
                                    dump.write(b'\n')
                            else:
                                size = 1
                                off = -size_or_off
                            computed_size += size
                            free_block_addr = free_block_addr - free_block_addr % page_size + off * 2
                            if size >= 1024/slob_unit_size: 
                                continue
                            free_space += size*slob_unit_size
                            space_counter += 1
                            range_counters[size/(256/slob_unit_size)] += 1
                    yield("free_slob_medium", "0-255", range_counters[0])
                    yield("free_slob_medium", "256-511", range_counters[1])
                    yield("free_slob_medium", "512-767", range_counters[2])
                    yield("free_slob_medium", "768-1023", range_counters[3])
                    print("------------ slob medium stats ----------------")
                    print("free space "+str(free_space)+" | free_mean_size "+str(free_space/space_counter)+" | PAGES "+str(len(medium_pages)))
                    print("-------------------- --------------- ----------")

                    # Enumerate the content of free_slob_large
                    range_counters = [0] * 5
                    free_space = 0
                    space_counter = 0
                    base = self._config.PAGE_SIZE / 4
                    for page in large_pages:
                        free_block_addr = page.freelist
                        computed_size = 0
                        while free_block_addr != 0x0 and computed_size < page.units:
                            size_or_off = obj.Object(size_type, offset = free_block_addr, vm = self.addr_space)
                            if size_or_off > 0:
                                size = size_or_off
                                off = obj.Object(size_type, offset = free_block_addr + slob_unit_size, vm = self.addr_space)
                                if (dump_list == "l" or dump_list == "a") and dump_file != None and size * slob_unit_size >= SLOB_BREAK2:
                                    block = self.addr_space.read(free_block_addr, size * slob_unit_size)
                                    header = 'Address: ' + hex(free_block_addr) + ', Size: ' + str(size * slob_unit_size) + '\n'
                                    header = header.encode('ascii')
                                    dump.write(header)
                                    dump.write(block)
                                    dump.write(b'\n')
                            else:
                                size = 1
                                off = -size_or_off
                            computed_size += size
                            free_block_addr = free_block_addr - free_block_addr % page_size + off * 2
                            if size >= page_size:
                                range_counters[4] += 1
                                continue
                            free_space += size*slob_unit_size
                            space_counter += 1
                    range_counters[size/(base/slob_unit_size)] += 1
                    yield("free_slob_large", "0-"+str(base-1), range_counters[0])
                    yield("free_slob_large", str(base)+"-"+str(base*2-1), range_counters[1])
                    yield("free_slob_large", str(base*2)+"-"+str(base*3-1), range_counters[2])
                    yield("free_slob_large", str(base*3)+"-"+str(base*4-1), range_counters[3])
                    if(range_counters[4]>0):
                        print "free_slob_large      "+str(range_counters[4])+" greater than a page(!?) <maybe wrong PAGE_SIZE>"
                    print("------------ slob large stats ----------------")
                    print("free space "+str(free_space)+" | free_mean_size "+str(free_space/space_counter)+" | PAGES "+str(len(large_pages)))

                    if dump_file != None:
                        dump.close()



    def render_text(self, outfd, data):
        linux_common.set_plugin_members(self)
        cache_chain = self.addr_space.profile.get_symbol("cache_chain")
        slab_caches = self.addr_space.profile.get_symbol("slab_caches")
        if (cache_chain or slab_caches) and not self.addr_space.profile.get_symbol("free_slob_small"):
            self.table_header(outfd, [("<name>", "<30"),
                                    ("<active_objs>", "<13"),
                                    ("<num_objs>", "<10"),
                                    ("<objsize>", "<10"),
                                    ("<objperslab>", "<12"),
                                    ("<pagesperslab>", "<15"),
                                    ("<active_slabs>", "<14"),
                                    ("<num_slabs>", "<7"),
                                    ])

            for info in data:
                self.table_row(outfd, info[0], info[1], info[2], info[3], info[4], info[5], info[6], info[7])
        else: #slob
            self.table_header(outfd, [("<list_name>", "<20"),
                                  ("<range (bytes)>", "<10"),
                                  ("<# free>", "<10")
                                 ])

            for info in data:
                self.table_row(outfd, info[0], info[1], info[2])
