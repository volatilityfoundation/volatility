# Volatility
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

"""
@author:       Joe Sylve
@license:      GNU General Public License 2.0 or later
@contact:      joe.sylve@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import volatility.protos as protos
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

 

class linux_slabinfo(linux_common.AbstractLinuxCommand):
    """Mimics /proc/slabinfo on a running machine"""    
    
    @staticmethod
    def get_kmem_cache(self, name):
        cache_chain = self.get_profile_symbol("cache_chain")
        slab_caches = self.get_profile_symbol("slab_caches")
        
        if cache_chain: #slab
            caches = obj.Object("list_head", offset=cache_chain, vm = self.addr_space)
            listm = "next"
        elif slab_caches: #slub
            #TODO: slub
            caches = obj.Object("list_head", offset=slab_caches, vm = self.addr_space)
            listm = "list"
            debug.error("Slub support is not implemented yet.")
            return None
        else:
            debug.error("Unknown or unimplemented slab type.")
            return None
            
        if name == "all":
            return caches.list_of_type("kmem_cache", listm)
        
        for cache in caches.list_of_type("kmem_cache", listm):
            if cache.get_name() == name:
                return cache
        
        return None

    def calculate(self):
        
        for cache in self.get_kmem_cache(self, "all"):
            if cache.get_type() == "slab":
                active_objs = 0
                active_slabs = 0
                num_slabs = 0
                shared_avail = 0
                
                for slab in cache.get_full_list():
                    active_objs += cache.num
                    active_slabs += 1
                
                for slab in cache.get_partial_list():
                    active_objs += slab.inuse
                    active_slabs += 1
            
                for slab in cache.get_free_list():
                    num_slabs += 1
            
                num_slabs += active_slabs
                num_objs = num_slabs * cache.num
                
                yield [cache.get_name(), active_objs, num_objs, cache.buffer_size, cache.num, 1 << cache.gfporder, active_slabs, num_slabs]
        
            elif cache.get_type() == "slub":
                # TODO: slub
                pass
                    
                    
    def render_text(self, outfd, data):
        outfd.write("{0:<30} {1:<13} {2:<10} {3:<10} {4:<12} {5:<15} {6:<14} {7}\n".format("<name>","<active_objs>", "<num_objs>", "<objsize>", "<objperslab>", "<pagesperslab>", "<active_slabs>", "<num_slabs>", "<sharedavail>"))
        for info in data:
            outfd.write("{0:<30} {1:<13} {2:<10} {3:<10} {4:<12} {5:<15} {6:<14} {7}\n".format(info[0], info[1], info[2], info[3], info[4], info[5], info[6], info[7]))
        
