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
import volatility.plugins.mac.lsmod as lsmod

class mac_notifiers(lsmod.mac_lsmod):
    """ Detects rootkits that add hooks into I/O Kit (e.g. LogKext) """

    def calculate(self):
        common.set_plugin_members(self)

        (kernel_symbol_addresses, kmods) = common.get_kernel_addrs(self)
        gnotify_addr = common.get_cpp_sym("gNotifications", self.addr_space.profile)
        gnotify_ptr = obj.Object("Pointer", offset = gnotify_addr, vm = self.addr_space)
        gnotifications = gnotify_ptr.dereference_as("OSDictionary")
        ents = obj.Object('Array', offset = gnotifications.dictionary, vm = self.addr_space, targetType = 'dictEntry', count = gnotifications.count)

        # walk the current set of notifications
        for ent in ents:

            if ent == None:
                continue

            key = str(ent.key.dereference_as("OSString"))

            # get the value
            valset = ent.value.dereference_as("OSOrderedSet")
            notifiers_ptrs = obj.Object('Array', offset = valset.array, vm = self.addr_space, targetType = 'Pointer', count = valset.count)
            
            for ptr in notifiers_ptrs:
                notifier = ptr.dereference_as("_IOServiceNotifier") 

                if notifier == None:
                    continue

                matches = self.get_matching(notifier)

                # this is the function that handles whatever the notification is for
                # this should be only in the kernel or in one of the known IOKit drivers for the specific kernel
                handler = notifier.handler

                good = common.is_known_address(handler, kernel_symbol_addresses, kmods)
                yield (good, key, notifier, matches)

    # returns the list of matching notifiers (serviceMatch) for a notifier as a string
    def get_matching(self, notifier):
        matches = []
    
        matching = notifier.matching
        ents = obj.Object('Array', offset = matching.dictionary, vm = self.addr_space, targetType = 'dictEntry', count = matching.count)

        for ent in ents:
            if ent == None:
                continue

            match = ent.value.dereference_as("OSString")            
            matches.append(str(match))

        return ",".join(matches)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Status", "10"), 
                                  ("Key", "30"), 
                                  ("Handler", "[addrpad]"), 
                                  ("Matches", "")])

        for (good, key, notifier, matches) in data:

            if good == 0:
                status = "UNKNOWN"
            else:
                status = "OK"

            self.table_row(outfd, status, key, notifier.handler, matches)
