# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.lsmod as linux_lsmod
import volatility.plugins.linux.common as linux_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_check_modules(linux_common.AbstractLinuxCommand):
    """Compares module list to sysfs info, if available"""

    def get_kset_modules(self):
        module_kset_addr = self.profile.get_symbol("module_kset")
        if not module_kset_addr:
            debug.error("This command is not supported by this profile.") 

        ret = {}

        module_kset = obj.Object("kset", offset = module_kset_addr, vm = self.addr_space)
    
        for kobj in module_kset.list.list_of_type("kobject", "entry"):
            kobj_off = self.profile.get_obj_offset("module_kobject", "kobj")
            mod_kobj = obj.Object("module_kobject", offset = kobj.v() - kobj_off, vm = self.addr_space)            
            mod = mod_kobj.mod

            name = kobj.name.dereference_as("String", length = 32)
            if name.is_valid() and kobj.kref.refcount.counter > 2:
                ret[str(name)] = mod
    
        return ret

    def calculate(self):
        linux_common.set_plugin_members(self)

        kset_modules = self.get_kset_modules()
        
        lsmod_modules = set([str(module.name) for (module, params, sects) in linux_lsmod.linux_lsmod(self._config).calculate()])
            
        for mod_name in set(kset_modules.keys()).difference(lsmod_modules):
            yield kset_modules[mod_name]

    def unified_output(self, data):
        return TreeGrid([("ModuleAddress", Address),
                       ("ModuleName", str)],
                        self.generator(data))

    def generator(self, data):
        for mod in data:
            yield (0, [Address(mod), str(mod.name)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Module Address", "[address]"), ("Core Address", "[address]"), ("Init Address", "[addreess]"), ("Module Name", "24")])
        for mod in data:
            self.table_row(outfd, mod, mod.module_core, mod.module_init, str(mod.name))
