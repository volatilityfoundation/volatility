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
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

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
    MAX_SLABS = 500
    MAX_ALIASES = 500
    MAX_NODES = 1024
    def get_type(self):
        return "slub"

    def get_size(self):
        return int(self.size())
    
    def get_nodes(self):
        off = self.cpu_slab
        inuse = self.size
        print("nodes offset"+str(off))
        print("size "+str(inuse))
        nodes = obj.Array("kmem_cache_node", offset=self.node.dereference(), vm = self.obj_vm)
        return nodes

    def _get_partial_list(self, offset):
        pNodes = obj.Object(theType = "Pointer", taregtType = "kmem_cache_node", offset = offset + self.obj_offset , vm = self.obj_vm, count = 1, name = "node")
        print(type(pNodes))
        nodes = pNodes.dereference_as("kmem_cache_node", length = self.MAX_NODES)
        print(type(nodes))
        
        for node in nodes:
            print(type(node))

        # for node in nodes:
        #     print("ciao")
        #     print(type(node))


        #     slabs = obj.Object("int", offset = node.size, vm = self.obj_vm)
        #     listm = "next"
        #     ret = [slab for slab in slabs.list_of_type("page", listm)]


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

    def get_all_kmem_caches(self):
        linux_common.set_plugin_members(self)
        cache_chain = self.addr_space.profile.get_symbol("cache_chain")
        slab_caches = self.addr_space.profile.get_symbol("slab_caches")

        if cache_chain: #slab
            caches = obj.Object("list_head", offset = cache_chain, vm = self.addr_space)
            listm = "next"
            ret = [cache for cache in caches.list_of_type("kmem_cache", listm)]
        elif slab_caches: #slub
            # debug.info("SLUB is currently unsupported.")
            caches = obj.Object("list_head", offset = slab_caches, vm = self.addr_space)
            listm = "list"
            print("testing")
            ret = [cache for cache in caches.list_of_type("kmem_cache", listm)]
        else:
            debug.error("Unknown or unimplemented slab type.")

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
                    # size = obj.Object('int', vm = cache.obj_vm, name = "size")
                    objperslabs = 0
                    pagesperslab = 0
                    node = cache.m('node')
                    #print node.d()
                    cache_node = obj.Object('kmem_cache_node', offset = node[0], vm = self.addr_space)
                    #print cache_node.nr_partial
                    #print hex(cache_node.partial.next)
                    page = obj.Object('page', offset = cache_node.partial.next, vm = self.addr_space)
                    print page.inuse
                    #print page.objects - page.inuse
                    #for i in node:
                    #    cache_node = obj.Object('kmem_cache_node', offset = i, vm = self.addr_space)
                    #    if cache_node.is_valid():
                    #        page = obj.Object('page', offset = cache_node.partial.next, vm = self.addr_space)
                    #        print page.freelist
                    #print hex(page.freelist)
                    #while page.next > 0x1000000000000000:
                    #    print page.freelist
                        #print page.members
                    #    page = obj.Object('page', offset = page.next, vm = self.addr_space)
                    #print list(self.addr_space.read(0xffff88007d008e00L, 192))
                    #print page.freelist
                    #print page.inuse
                    #print page.objects
                    #print page.counters
                    #if page.index == 0:
                    #    print 0
                    #else: 
                    #    print page.counters / page.index
                    #print page.pages
                    #print page.pobjects
                    page2 = obj.Object('page', offset = page.next, vm = self.addr_space)
                    print page2.inuse
                    #print page2.counters
                    #print page2.inuse
                    #print page2.freelist
                    #print list(self.addr_space.read(0xffff88007d002900, 10))
                    #print hex(page.freelist)
                    #print cache.m('node').d()
                    #for i in cache.members:
                    #    print i
                    #print cache.members['node'][0]
                    #print cache.m("name")
                    #node_off = self.profile.get_obj_offset("kmem_cache", "node")
                    # print("nodeoff "+str(node_off))
                    # for slab in cache._get_partial_list(node_off):
                    #     active_objs += slab.objects
                    #     active_slabs += 1

                    #cache._get_partial_list(node_off)

                    # for slab in cache._get_free_list():
                    #     num_slabs += 1

                    yield [cache.get_name(),
                            active_objs,
                            num_objs,
                            cache.m("size"),
                            objperslabs,
                            pagesperslab,
                            active_slabs,
                            num_slabs]



    def render_text(self, outfd, data):
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
