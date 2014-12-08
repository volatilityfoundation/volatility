import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.common as common
import volatility.plugins.malware.devicetree as dtree
import volatility.win32.modules as modules
import volatility.win32.tasks as tasks

class drivermodule(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('ADDR', short_option = 'a', default = None,
                          help = 'Show info on VAD at or containing this address',
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
                driver_name = driver.get_object_header().NameInfo.Name
                owning_module = tasks.find_module(mods, mod_addrs, mods.values()[0].obj_vm.address_mask(driver.DriverStart))

                if owning_module:
                    module_name = owning_module.BaseDllName or owning_module.FullDllName
                else:
                    module_name = "UNKNOWN"

                yield (module_name, driver_name)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Module", "36"), ("Driver", "")])

        for module_name, driver_name in data:
            self.table_row(outfd, module_name, driver_name)
       



