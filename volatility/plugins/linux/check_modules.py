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
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.lsmod as linux_lsmod
import volatility.plugins.linux.common as linux_common

'''
This plugin finds rootkits that break themselves from the module list but not sysfs
I have never found a rootkit that actually removes it self from sysfs
So on a live system they are hidden from lsmod & /proc/modules
But can still be found under /sys/modules/
We perform the same differnecing with the in-memory data structures
'''
class linux_check_modules(linux_common.AbstractLinuxCommand):
    """Compares module to list to sysfs info, if avaiable"""

    def get_kset_modules(self):
        module_kset_addr = self.profile.get_symbol("module_kset")
        if not module_kset_addr:
            debug.error("This command is not supported by this profile.") 

        ret = set()

        module_kset = obj.Object("kset", offset = module_kset_addr, vm = self.addr_space)
    
        for kobj in module_kset.list.list_of_type("kobject", "entry"):
            name = kobj.name.dereference_as("String", length=32)
            if name.is_valid() and kobj.kref.refcount.counter > 2:
                ret.add(str(name))
    
        return ret

    def calculate(self):
        linux_common.set_plugin_members(self)

        kset_modules  = self.get_kset_modules()
        
        lsmod_modules = set([str(module.name) for (module, params, sects) in linux_lsmod.linux_lsmod(self._config).calculate()])
            
        for mod_name in kset_modules.difference(lsmod_modules):
            yield mod_name

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Module Name","")])
        for name in data:
            self.table_row(outfd, name)

