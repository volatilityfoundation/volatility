# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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

import volatility.obj as obj
import volatility.plugins.mac.common as common
import volatility.utils as utils
import volatility.plugins.mac.pstasks as pstasks 
from volatility.renderers import TreeGrid

class mac_contacts(pstasks.mac_tasks):
    """Gets contact names from Contacts.app"""

    def calculate(self):
        common.set_plugin_members(self)

        procs = pstasks.mac_tasks.calculate(self)

        for proc in procs:
            space = proc.get_process_address_space()
            for map in proc.get_proc_maps():

                # only read/write without filebacks 
                if not (map.get_perms() == "rw-" and not map.get_path()):
                    continue

                # check the header for sqlite3 signature 
                header = space.zread(map.links.start, 32)
                if "SQLite format" not in header:
                    continue

                # get the whole sqlite3 data now 
                data = space.zread(map.links.start, 
                                  map.links.end - map.links.start)
                
                for offset in utils.iterfind(data, ":ABPerson"):
                    person = obj.Object("String", 
                                        offset = map.links.start + offset, 
                                        vm = space, encoding = "utf8", 
                                        length = 256)
                    yield proc, person
    
    def unified_output(self, data):
        return TreeGrid([("Contact", str),
                         ],
                         self.generator(data))
                         
    def generator(self, data):
        for (proc, person) in data:
            # strip the header from the string 
            person = str(person)[len(":ABPerson"):]

            # take a maximum of eight parts  
            items = " ".join(person.split(" ")[:8])
            
            yield(0, [str(items),])            

    def render_text(self, outfd, data):
        for (proc, person) in data:
            # strip the header from the string 
            person = str(person)[len(":ABPerson"):]

            # take a maximum of eight parts  
            items = " ".join(person.split(" ")[:8])
            
            outfd.write("{0}\n".format(items))
