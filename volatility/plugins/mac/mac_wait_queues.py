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
import mac_common
import sys

class mac_wait_queues(mac_common.AbstractMacCommand):

    def calculate(self):

        print "broke for now, do not use"
        sys.exit(1)

        #proc = thread.task.bsd_info

        cnt = 256

        wait_queues_addr = self.smap["_wait_queues"]

        wait_queues = obj.Object(theType = 'Array', offset = wait_queues_addr, vm = self.addr_space, targetType = 'wait_queue', count = cnt)

        for i in xrange(0, cnt):

            wait_queue = obj.Object("wait_queue", offset=wait_queues[i].obj_offset, vm=self.addr_space)

            if not wait_queue:
                continue

            print "valid queue at %d" % wait_queue.obj_offset

            nextptr = wait_queue.opaquep[0]
       
            print "next: %d" % nextptr
 
            first = nextptr

            wq = obj.Object("queue_entry", offset=nextptr, vm=self.addr_space)

            while wq != first:

                print wq

                wq = wq.next 

            print "done first queue"
            sys.exit(1) 


    def render_text(self, outfd, data):
        
        for blah in data:
            
            pass
