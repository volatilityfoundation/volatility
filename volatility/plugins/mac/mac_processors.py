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

import volatility.obj as obj
import volatility.plugins.mac.common as common
import volatility.debug as debug
import sys

class mac_get_processors(common.AbstractMacCommand):

    def calculate(self):

        debug.error("broken and in testing, do not use yet")
    
        ctr = 0        

        pset = obj.Object("processor_set", offset = self.smap["_pset0"], vm = self.addr_space)

        while pset != None:

            '''
            actq = obj.Object("queue_entry", offset=pset.active_queue.obj_offset, vm=self.addr_space)

            checkaddr = actq.obj_offset
            curq      = actq.next

            print "%x | %x" % (checkaddr, actq.v())

            for i in xrange(0, 11):

                print "%x | %x" % (curq.v(), curq.obj_offset)

                if curq == checkaddr:
                    print "STOP"

                curq = obj.Object("queue_entry", offset=curq.next.dereference().v(), vm=self.addr_space)

            sys.exit(1)


            while curq.v() != checkaddr:

                print "%.08x | %.08x || %.08x" % (curq.obj_offset, curq.v(), checkaddr)

                #current = obj.Object("processor", offset=curq.obj_offset, vm=self.addr_space)

                curq = curq.next

                ctr = ctr + 1

                if ctr == 11:
                    print "fail"
                    sys.exit(1)
            '''
            print "num procs: %d" % pset.online_processor_count

            pset = pset.pset_list

    # this plugin really shouldn't be called on its own
    def render_text(self, outfd, data):
        
        for processor in data:
            print "%#x" % processor.obj_offset

class mac_runq(mac_get_processors):

    def calculate(self):
        debug.error("broken and in testing, do not use yet")
 
        sched_str = mac_common.get_string(self.smap["_sched_string"], self.addr_space)

        if sched_str == "traditional":
            func   = self.handle_runq
    
        elif sched_str == "grrr":
            print "grrr is currently not supported"
        
        else:
            print "%s is not currently supported" % sched_string

        procs = mac_get_processors.calculate(self)

        for a in procs:
            print a

    def render_text(self, outfd, data):
        for blah in data:
            pass

    def handle_runq(self):
        pass
