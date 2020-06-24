import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_slobinfo(linux_common.AbstractLinuxCommand):
    """Information about the status of the SLOB allocator"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PAGE_SIZE', short_option = 'p', default = 0x1000,
                          help = 'The page size of the analyzed system',
                          action = 'store', type = 'int')
        self._config.add_option('DUMP_FREE_LIST', short_option = 'L', default = None,
                          help = 'Select the free list to dump (s,m,l)',
                          action = 'store', type = 'str')

    def calculate(self):
        linux_common.set_plugin_members(self)

        # Set the size of a slob unit in bytes depending on the page size
        page_size = self._config.PAGE_SIZE
        dump_list = self._config.DUMP_FREE_LIST
        page_list = None
        if page_size <= 32767 * 2:
            slob_unit_size = 2
        else:
            slob_unit_size = 4

	# Find offsets of the 3 list_head objects for the SLOB page lists
        free_slob_small = self.addr_space.profile.get_symbol("free_slob_small")
        free_slob_medium = self.addr_space.profile.get_symbol("free_slob_medium")
        free_slob_large = self.addr_space.profile.get_symbol("free_slob_large")

        # Create the list_head objects
        slob_small = obj.Object("list_head", offset = free_slob_small, vm = self.addr_space)
        slob_medium = obj.Object("list_head", offset = free_slob_medium, vm = self.addr_space)
        slob_large = obj.Object("list_head", offset = free_slob_large, vm = self.addr_space)

        # Gather the pages on the lists
        small_pages = [slob for slob in slob_small.list_of_type("page", "slab_list")]
        medium_pages = [slob for slob in slob_medium.list_of_type("page", "slab_list")]
        large_pages = [slob for slob in slob_large.list_of_type("page", "slab_list")]

        if(dump_list == 's'):
            page_list = small_pages
        elif(dump_list == 'm'):
            page_list = medium_pages
        elif(dump_list == 'l'):
            page_list = large_pages
        if(page_list != None):
            for page in page_list:
                free_block_addr = page.freelist
                computed_size = 0
                while free_block_addr != 0x0 and computed_size < page.units:
                    size_or_off = obj.Object('short', offset = free_block_addr, vm = self.addr_space)
                    if size_or_off > 0:
                        size = size_or_off
                        off = obj.Object('short', offset = free_block_addr + slob_unit_size, vm = self.addr_space)
                        # print(off)

                        for i in range(size * slob_unit_size / 4):
                            o = obj.Object('int', offset = free_block_addr + slob_unit_size + i * 4, vm = self.addr_space)
                            # print(self.addr_space)
                            # print(size)
                            # print(free_block_addr + slob_unit_size + i)
                            print(o)
                    else:
                        size = 1
                        off = -size_or_off
                    computed_size += size
                    free_block_addr = free_block_addr - free_block_addr % page_size + off * 2

        
        # Enumerate the content of free_slob_small
        range_counters = [0] * 4
        free_space = 0
        space_counter = 0
        for page in small_pages:
            free_block_addr = page.freelist
            computed_size = 0
            while free_block_addr != 0x0 and computed_size < page.units:
                size_or_off = obj.Object('short', offset = free_block_addr, vm = self.addr_space)
                if size_or_off > 0:
                    size = size_or_off
                    off = obj.Object('short', offset = free_block_addr + slob_unit_size, vm = self.addr_space)
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
                size_or_off = obj.Object('short', offset = free_block_addr, vm = self.addr_space)
                if size_or_off > 0:
                    size = size_or_off
                    off = obj.Object('short', offset = free_block_addr + slob_unit_size, vm = self.addr_space)
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
                size_or_off = obj.Object('short', offset = free_block_addr, vm = self.addr_space)
                if size_or_off > 0:
                    size = size_or_off
                    off = obj.Object('short', offset = free_block_addr + slob_unit_size, vm = self.addr_space)
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



    def render_text(self, outfd, data):
        self.table_header(outfd, [("<list_name>", "<20"),
                                  ("<range (bytes)>", "<10"),
                                  ("<# free>", "<10")
                                 ])

        for info in data:
            self.table_row(outfd, info[0], info[1], info[2])
