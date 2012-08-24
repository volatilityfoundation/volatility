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
import volatility.plugins.linux.common as linux_common

class linux_lsmod(linux_common.AbstractLinuxCommand):
    """Gather loaded kernel modules"""

    def __init__(self, config, *args): 

        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('SECTIONS', short_option = 'S', default = None, help = 'show section addresses', action = 'store_true')

    def get_param_val(self, param):
        
        ints = {
                self.smap["param_get_invbool"] : "int",
                self.smap["param_get_bool"]    : "int",
                self.smap["param_get_ulong"]   : "unsigned long",
                self.smap["param_get_long"]    : "long",
                self.smap["param_get_uint"]    : "unsigned int",
                self.smap["param_get_ushort"]  : "unsigned short",
                self.smap["param_get_short"]   : "short",
                self.smap["param_get_byte"]    : "char",
               }

        getfn = param.get

        # FIXME
        if getfn == self.smap["param_array_get"]:
            val = "param_array_get"

        elif getfn == self.smap["param_get_string"]:
            val = param.str.dereference_as("String", length=param.str.maxlen)
        
        elif getfn == self.smap["param_get_charp"]:
            v = self.addr_space.read(param.arg, 256)
            val = ''.join(["%c" % ord(c) for c in v if 30 < ord(c) < 128])
               
 
        elif getfn.v() in ints:
            val = obj.Object(ints[getfn.v()], offset=param.arg.obj_offset, vm=self.addr_space)

        else:
            print "Unknown get_fn: %x" % getfn
            return None

        return val

    def get_params(self, module):

        param_array = obj.Object(theType = 'Array', offset = module.kp, vm = self.addr_space, targetType = 'kernel_param', count = module.num_kp)

        for param in param_array:

            val = self.get_param_val(param)

            print "name: %s val: %s" % (param.name.dereference_as("String", length=255), val) 
            
    
    def get_sections(self, module):

        attrs = obj.Object(theType = 'Array', offset = module.sect_attrs.attrs.obj_offset, vm = self.addr_space, targetType = 'module_sect_attr', count = module.sect_attrs.nsections)
    
        sects = []

        for attr in attrs:
            
            name = attr.name.dereference_as("String", length=255)

            sects.append((name, attr.address))

        return sects

    def calculate(self):

        modules_addr = self.get_profile_symbol("modules")

        modules = obj.Object("list_head", vm = self.addr_space, offset = modules_addr)

        # walk the modules list
        for module in modules.list_of_type("module", "list"):

            #if str(module.name) != "lime":
            #    continue

            # FIXME - on hold until anon unions can be accessed
            # params = self.get_params(module)

            sections = self.get_sections(module)

            yield (module, sections)

    def render_text(self, outfd, data):

        for (module, sections)  in data:
            outfd.write("{0:s} {1:d}\n".format(module.name, module.init_size + module.core_size))

            if self._config.SECTIONS:

                for sect in sections:
        
                    (name, address) = sect

                    outfd.write("\t{0:30s} {1:#x}\n".format(name, address))
            
    # returns a list of tuples of (name, .text start, .text end) for each module
    # include_list can contain a list of only the modules wanted by a plugin
    def get_modules(self, include_list=[]):

        ret = []

        for (module, _sections) in self.calculate():

            if len(include_list) == 0 or str(module.name) in include_list:

                ret.append(("%s" % module.name, module.module_core, module.module_core + module.module_core + module.core_size))

        return ret
   
    # This returns the name of the module that contains an address or None
    # The module_list parameter comes from a call to get_modules
    # This function will be updated after 2.2 to resolve symbols within the module as well
    def address_in_module(self, module_list, address):

        ret = None

        for (name, start, end) in module_list:
            
            if start <= address < end:
                
                ret = name
                break

        return ret



