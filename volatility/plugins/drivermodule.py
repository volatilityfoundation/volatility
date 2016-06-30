# Volatility
# Copyright (c) 2008-2015 Volatility Foundation
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
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.common as common
import volatility.plugins.malware.devicetree as dtree
import volatility.win32.modules as modules
import volatility.win32.tasks as tasks
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class drivermodule(common.AbstractWindowsCommand):
    """Associate driver objects to kernel modules"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('ADDR', short_option = 'a', default = None,
                          help = 'Show info on module at or containing this address',
                          action = 'store', type = 'int')
 
    def calculate(self):
        addr_space = utils.load_as(self._config)

        modlist = list(modules.lsmod(addr_space))
        mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in modlist)
        mod_addrs = sorted(mods.keys())
            
        drivers = dtree.DriverIrp(self._config).calculate()    
        found_driver = "UNKNOWN"

        if self._config.ADDR:
            find_address = self._config.ADDR
            
            found_module = tasks.find_module(mods, mod_addrs, mods.values()[0].obj_vm.address_mask(find_address))
            if found_module:
                found_module = found_module.BaseDllName or found_module.FullDllName
            else:
                found_module = "UNKNOWN"

            for driver in drivers:
                if driver.DriverStart <= find_address < driver.DriverStart + driver.DriverSize:
                    header = driver.get_object_header()
                    found_driver = header.NameInfo.Name
                    break
            
            yield (found_module, found_driver)

        else:                
            for driver in drivers:
                driver_name  = str(driver.get_object_header().NameInfo.Name or '')
                service_key = str(driver.DriverExtension.ServiceKeyName or '')
                driver_name3 = str(driver.DriverName or '')
                
                owning_module = tasks.find_module(mods, mod_addrs, mods.values()[0].obj_vm.address_mask(driver.DriverStart))
                if owning_module:
                    module_name = owning_module.BaseDllName or owning_module.FullDllName
                else:
                    module_name = "UNKNOWN"

                yield (module_name, driver_name, service_key, driver_name3)

    def generator(self, data):

        for module_name, driver_name, service_key, driver_name3 in data:
            yield( 0, [str(module_name), str(driver_name), str(service_key), str(driver_name3)])

    def unified_output(self, data):
        return TreeGrid([("Module", str),
                         ("Driver", str),
                         ("Alt. Name", str),
                         ("Service Key", str)],
                        self.generator(data))

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Module", "36"), ("Driver", "24"), ("Alt. Name", "24"), ("Service Key", "")])

        for module_name, driver_name, service_key, driver_name3 in data:
            self.table_row(outfd, module_name, driver_name, service_key, driver_name3)
       



