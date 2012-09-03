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
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.plugins.linux.common as linux_common
import volatility.obj as obj
import sys

class r_ent(object):

    def __init__(self, dest, gw, mask, devname):
        self.dest = dest
        self.gw = gw
        self.mask = mask
        self.devname = devname
            
# TODO needs testing!!!
# based on code from pykdump
class linux_route(linux_common.AbstractLinuxCommand):
    '''Lists routing table'''

    def calculate(self):
        fib_tables = self.get_fib_tables()

        for fib_table in fib_tables:

            for rent in self.get_fib_entries(fib_table):
                yield (rent.dest, rent.gw, rent.mask, rent.devname)
        
    def render_text(self, outfd, data):

        self.table_header(outfd, [("Destination", "15"), 
                                  ("Gateway", "15"), 
                                  ("Mask", "15"), 
                                  ("Interface", "")])
                                  
        for dest, gw, mask, devname in data:
            self.table_row(outfd, dest.cast("IpAddress"), gw.cast("IpAddress"), mask.cast("IpAddress"), devname)

    def get_fib_entries(self, table):
        
        fn_hash = obj.Object("fn_hash", offset = table.tb_data.obj_offset, vm = self.addr_space)
        zone_list = fn_hash.fn_zone_list

        for r in self.walk_zone_list(zone_list):
            yield r

    def walk_zone_list(self, zone_list):

        print "-------------------------------------------------------"
        
        for fn_zone in linux_common.walk_internal_list("fn_zone", "fz_next", zone_list, self.addr_space):
            
            mask = fn_zone.fz_mask
            hash_head = fn_zone.fz_hash
            array_size = fn_zone.fz_divisor

            head_array = obj.Object(theType = "Array", offset = hash_head, vm = self.addr_space, targetType = 'hlist_head', count = array_size)
 
            for head_list in head_array:

                if head_list and head_list.first:                
                    print "first"
            
                    for dest, gw, devname in self.parse_fib_node(head_list.first):
                        print "yielding r_ent"
                        yield r_ent(dest, gw, mask, devname)
                
    def parse_fib_node(self, first):
        
        fnptr = first

        while fnptr:

            fnode = obj.Object("fib_node", offset = fnptr, vm = self.addr_space)

            for alias in fnode.fn_alias.list_of_type("fib_alias", "fa_list"):

                dest = fnode.fn_key
                fi = alias.fa_info
            
                try:
                    ent = obj.Object("fib_nh", offset = fi.fib_nh.obj_offset, vm = self.addr_space)
                except:
                    ## FIXME: what exception are we trying to catch here? If we're 
                    ## just trying to detect when fi or fi.fib_nh are invalid pointers
                    ## then do something like this instead:
                    ##
                    ##     if not fi.is_valid() or not fi.fib_nh.is_valid():
                    ##         yield (dest, 0, "bad")
                    ##     else:
                    ##         ## <the rest> 
                    ## 
                    yield (dest, 0, "bad")    
                    continue

                if ent.nh_dev:
                    devname = ent.nh_dev.name
                else:
                    devname = '*'

                gw = ent.nh_gw

                yield (dest, gw, devname)    
  
            fnptr = fnptr.next

    def get_fib_table(self):

        fib_table_addr = self.get_profile_symbol("fib_table_hash")
        init_net_addr = self.get_profile_symbol("init_net")

        # get pointer to table
        if fib_table_addr:
            fib_table_ptr = self.get_profile_symbol("fib_table_hash")

        elif init_net_addr:
            
            init_net = obj.Object("net", offset = init_net_addr, vm = self.addr_space) 
            fib_table_ptr = obj.Object("Pointer", offset = init_net.ipv4.fib_table_hash, vm = self.addr_space)
                
        else:
            # ikelos what is the proper expection to raise?
            print "BAD: Cannot find fib_table_hash.."
            sys.exit(1)

        # get the size
        if self.get_profile_symbol("fib_table_hash"): # TODO "if fib_table_hash symbol is an array"
            fib_tbl_sz = -1 # BUG make it size of the array
            raise AttributeError, "please file a bug with kernel version and distribution that triggered this message"

        elif self.profile.obj_has_member("fib_table","fib_power"):
            fib_tbl_sz = 256

        else:
            fib_tbl_sz = 2

        fib_table = obj.Object(theType = 'Array', offset = fib_table_ptr, 
            vm = self.addr_space, targetType = 'hlist_head', count = fib_tbl_sz)

        return (fib_table, fib_tbl_sz)

    def get_fib_tables(self):

        ret = []
        
        fib_tables_addr = self.get_profile_symbol("fib_tables")

        if fib_tables_addr:
            fib_tables  = obj.Object(theType = "Array", offset = fib_tables_addr, vm = self.addr_space, targetType = 'fib_table', count = 256)
            ret = [f for f in fib_tables if f]

        else:
            
            (fib_table, tbl_sz) = self.get_fib_table()

            print "tbl_sz: {0}".format(tbl_sz)

            for i in xrange(0, tbl_sz):
                fb = fib_table[i]

                if fb and fb.first:
                    
                    for tb in fb.first.list_of_type("fib_table", "tb_hlist"):
                        print "Appending {0:#x}".format(tb.v())
                        ret.append(tb)
                    
        return ret 
                      




 
