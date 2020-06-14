import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_slobinfo(linux_common.AbstractLinuxCommand):
    def calculate(self):
        linux_common.set_plugin_members(self)

        free_slob_small = self.addr_space.profile.get_symbol("free_slob_small")
        free_slob_medium = self.addr_space.profile.get_symbol("free_slob_medium")
        free_slob_large = self.addr_space.profile.get_symbol("free_slob_large")
        slob_small = obj.Object("list_head", offset = free_slob_small, vm = self.addr_space)
        slob_medium = obj.Object("list_head", offset = free_slob_medium, vm = self.addr_space)
        slob_large = obj.Object("list_head", offset = free_slob_large, vm = self.addr_space)
        slobs = [slob for slob in slob_small.list_of_type("page", "slab_list")]
        print 'slob 0 s_mem ' + hex(slobs[0].s_mem)
        print 'slob 1 s_mem ' + hex(slobs[1].s_mem)
        print 'slob 2 s_mem ' + hex(slobs[2].s_mem)
        print 'slob 3 s_mem ' + hex(slobs[3].s_mem)
        print 'slob 1 addr '  + hex(slobs[0].slab_list.next)
        print 'slob 2 addr '  + hex(slobs[1].slab_list.next)
        print 'slob 1 units '  + hex(slobs[1].units)
        print 'slob 0 units ' + hex(slobs[0].units)
        print 'slob 2 units ' + hex(slobs[2].units)
        print 'slob 0 freelist ' + hex(slobs[0].freelist)
        print 'slob 1 freelist ' + hex(slobs[1].freelist)
        print 'slob 2 freelist ' + hex(slobs[2].freelist)
        size = obj.Object('short', offset = slobs[0].freelist, vm = self.addr_space)
        print size
        off = obj.Object('short', offset = slobs[0].freelist + 2, vm = self.addr_space)
        print off
        size = obj.Object('short', offset = (slobs[0].freelist & 0xfffffffffffff000) + off*2, vm = self.addr_space)
        print size
        off = obj.Object('short', offset = (slobs[0].freelist & 0xfffffffffffff000) + off*2 + 2, vm = self.addr_space)
        print off
        size = obj.Object('short', offset = (slobs[0].freelist & 0xfffffffffffff000) + off*2, vm = self.addr_space)
        print size
        print len(slobs)
        yield(1)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("<name>", "<30")])

        for info in data:
            self.table_row(outfd, info)
