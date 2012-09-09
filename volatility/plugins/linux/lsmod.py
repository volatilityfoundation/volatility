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
import volatility.plugins.linux.common as linux_common

class linux_lsmod(linux_common.AbstractLinuxCommand):
    """Gather loaded kernel modules"""

    def __init__(self, config, *args): 

        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('SECTIONS', short_option = 'S', default = None, help = 'show section addresses', action = 'store_true')
        self._config.add_option('PARAMS', short_option = 'P', default = None, help = 'show module parameters', action = 'store_true')

    def get_param_val(self, param, over = 0):
        
        ints = {
                self.get_profile_symbol("param_get_invbool", sym_type = "Pointer") : "int",
                self.get_profile_symbol("param_get_bool",    sym_type = "Pointer") : "int",
                self.get_profile_symbol("param_get_int",     sym_type = "Pointer") : "int",
                self.get_profile_symbol("param_get_ulong",   sym_type = "Pointer") : "unsigned long",
                self.get_profile_symbol("param_get_long",    sym_type = "Pointer") : "long",
                self.get_profile_symbol("param_get_uint",    sym_type = "Pointer") : "unsigned int",
                self.get_profile_symbol("param_get_ushort",  sym_type = "Pointer") : "unsigned short",
                self.get_profile_symbol("param_get_short",   sym_type = "Pointer") : "short",
                self.get_profile_symbol("param_get_byte",    sym_type = "Pointer") : "char",
               }

        getfn = param.get

        if getfn == 0:
            val = ""

        elif getfn == self.get_profile_symbol("param_array_get"):  

            val = ""
            
            arr = param.arr
            overwrite = param.arr

            if arr.num:
                max = arr.num.dereference()
            else:
                max = arr.max

            for i in range(max):

                if i > 0:
                    val = val + ","

                arg = offset = arr.elem + arr.elemsize * i
                overwrite.arg = arg

                mret = self.get_param_val(overwrite)
                val = val + str(mret)

        elif getfn == self.get_profile_symbol("param_get_string"):
            val = param.str.dereference_as("String", length = param.str.maxlen)
        
        elif getfn == self.get_profile_symbol("param_get_charp"):
            addr = obj.Object("Pointer", offset = param.arg, vm = self.addr_space)
            if addr == 0:
                val = "(null)"
            else:
                val  = addr.dereference_as("String", length=256) 

        elif getfn.v() in ints:
            val = obj.Object(ints[getfn.v()], offset = param.arg, vm = self.addr_space)

            if getfn == self.get_profile_symbol("param_get_bool"):
                if val:
                    val = 'Y'
                else:
                    val = 'N'

            if getfn == self.get_profile_symbol("param_get_invbool"):
                if val:
                    val = 'N'
                else:
                    val = 'Y'

        else:
            print "Unknown get_fn: {0:#x}".format(getfn)
            return None

        return val

    def get_params(self, module):
        
        param_array = obj.Object(theType = 'Array', offset = module.kp, vm = self.addr_space, targetType = 'kernel_param', count = module.num_kp)

        params = ""

        for param in param_array:

            val = self.get_param_val(param)

            params = params + "{0}={1} ".format(param.name.dereference_as("String", length = 255), val)
    
        return params

    def get_sections(self, module):

        attrs = obj.Object(theType = 'Array', offset = module.sect_attrs.attrs.obj_offset, vm = self.addr_space, targetType = 'module_sect_attr', count = module.sect_attrs.nsections)
    
        sects = []

        for attr in attrs:
            
            name = attr.name.dereference_as("String", length = 255)

            sects.append((name, attr.address))

        return sects

    def calculate(self):
        linux_common.set_plugin_members(self)
        modules_addr = self.get_profile_symbol("modules")

        modules = obj.Object("list_head", vm = self.addr_space, offset = modules_addr)

        # walk the modules list
        for module in modules.list_of_type("module", "list"):

            #if str(module.name) == "rootkit":
            #    continue

            if self._config.PARAMS:
            
                if not hasattr(module, "kp"):
                    debug.error("Gathering module parameters is not supported in this profile.")

                params = self.get_params(module)
            else:
                params = ""

            if self._config.SECTIONS:
                sections = self.get_sections(module)
            else:
                sections = []

            yield (module, sections, params)

    def render_text(self, outfd, data):

        for (module, sections, params)  in data:
            outfd.write("{0:s} {1:d}\n".format(module.name, module.init_size + module.core_size))

            # will be empty list if not set on command line
            for sect in sections:
    
                (name, address) = sect

                outfd.write("\t{0:30s} {1:#x}\n".format(name, address))
       
            # will be "" if not set, otherwise will be space seperated
            if params != "":
        
                for param in params.split():
                    outfd.write("\t{0:100s}\n".format(param))            
        
    # returns a list of tuples of (name, .text start, .text end) for each module
    # include_list can contain a list of only the modules wanted by a plugin
    def get_modules(self, include_list = []):

        ret = []

        for (module, _sections, _params) in self.calculate():

            if len(include_list) == 0 or str(module.name) in include_list:

                start = module.module_core
                end   = start +  module.core_size
                ret.append(("%s" % module.name, start, end))

        return ret
   

