import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_slobinfo(linux_common.AbstractLinuxCommand):
    """Information about the status of the SLOB allocator"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PAGE_SIZE', short_option = 'p', default = 0x1000,
                          help = 'The page size of the analyzed system',
                          action = 'store', type = 'int')

    def calculate(self):
        linux_common.set_plugin_members(self)

        # Set the size of a slob unit in bytes depending on the page size
        page_size = self._config.PAGE_SIZE
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

        # Gather the pages on the free_slob_small list
        small_pages = [slob for slob in slob_small.list_of_type("page", "slab_list")]
        
        # First free object size/offset
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
        print len(small_pages)
        yield(1)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("<name>", "<30")])

        for info in data:
            self.table_row(outfd, info)
