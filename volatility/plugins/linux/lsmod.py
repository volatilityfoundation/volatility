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

import re, os
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

class linux_lsmod(linux_common.AbstractLinuxCommand):
    """Gather loaded kernel modules"""

    def __init__(self, config, *args, **kwargs):

        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('SECTIONS', short_option = 'S', default = None, help = 'show section addresses', action = 'store_true')
        self._config.add_option('PARAMS', short_option = 'P', default = None, help = 'show module parameters', action = 'store_true')

    def get_param_val(self, param, _over = 0):

        ints = {
                self.addr_space.profile.get_symbol("param_get_invbool") : "int",
                self.addr_space.profile.get_symbol("param_get_bool") : "int",
                self.addr_space.profile.get_symbol("param_get_int") : "int",
                self.addr_space.profile.get_symbol("param_get_ulong") : "unsigned long",
                self.addr_space.profile.get_symbol("param_get_long") : "long",
                self.addr_space.profile.get_symbol("param_get_uint") : "unsigned int",
                self.addr_space.profile.get_symbol("param_get_ushort") : "unsigned short",
                self.addr_space.profile.get_symbol("param_get_short") : "short",
                self.addr_space.profile.get_symbol("param_get_byte") : "char",
               }

        getfn = param.get

        if getfn == 0:
            val = ""

        elif getfn == self.addr_space.profile.get_symbol("param_array_get"):

            val = ""

            arr = param.arr
            overwrite = param.arr

            if arr.num:
                maxi = arr.num.dereference()
            else:
                maxi = arr.max

            for i in range(maxi):

                if i > 0:
                    val = val + ","

                arg = arr.elem + arr.elemsize * i
                overwrite.arg = arg

                mret = self.get_param_val(overwrite)
                val = val + str(mret or '')

        elif getfn == self.addr_space.profile.get_symbol("param_get_string"):
            val = param.str.dereference_as("String", length = param.str.maxlen)

        elif getfn == self.addr_space.profile.get_symbol("param_get_charp"):
            addr = obj.Object("Pointer", offset = param.arg, vm = self.addr_space)
            if addr == 0:
                val = "(null)"
            else:
                val = addr.dereference_as("String", length = 256)

        elif getfn.v() in ints:
            val = obj.Object(ints[getfn.v()], offset = param.arg, vm = self.addr_space)

            if getfn == self.addr_space.profile.get_symbol("param_get_bool"):
                if val:
                    val = 'Y'
                else:
                    val = 'N'

            if getfn == self.addr_space.profile.get_symbol("param_get_invbool"):
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

    def get_sect_count(self, grp):
        idx = 0

        arr = obj.Object(theType = 'Array', offset = grp.attrs, vm = self.addr_space, targetType = 'Pointer', count = 25)

        while arr[idx]:
            idx = idx + 1

        return idx

    def get_sections(self, module):
        if hasattr(module.sect_attrs, "nsections"):
            num_sects = module.sect_attrs.nsections
        else:
            num_sects = self.get_sect_count(module.sect_attrs.grp)

        attrs = obj.Object(theType = 'Array', offset = module.sect_attrs.attrs.obj_offset, vm = self.addr_space, targetType = 'module_sect_attr', count = num_sects)

        sects = []

        for attr in attrs:
            name = attr.get_name()

            sects.append((name, attr.address))

        return sects

    def calculate(self):
        linux_common.set_plugin_members(self)
        modules_addr = self.addr_space.profile.get_symbol("modules")

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
    def get_modules(self, include_list = None):

        if not include_list:
            include_list = []

        ret = []

        for (module, _sections, _params) in self.calculate():

            if len(include_list) == 0 or str(module.name) in include_list:

                start = module.module_core
                end = start + module.core_size
                ret.append(("%s" % module.name, start, end))

        return ret

class linux_moddump(linux_common.AbstractLinuxCommand):
    """Extract loaded kernel modules"""
    
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        
        config.add_option('DUMP-DIR', short_option = 'D', default = None,       
                      help = 'Directory in which to dump the files',
                      action = 'store', type = 'string')
        config.add_option('REGEX', short_option = 'r',
                      help = 'Dump modules matching REGEX',
                      action = 'store', type = 'string')
        config.add_option('IGNORE-CASE', short_option = 'i',
                      help = 'Ignore case in pattern match',
                      action = 'store_true', default = False)

    def calculate(self):
        linux_common.set_plugin_members(self)
        modules_addr = self.addr_space.profile.get_symbol("modules")
        modules = obj.Object("list_head", vm = self.addr_space, offset = modules_addr)
    
        if self._config.REGEX:
            try:
                if self._config.IGNORE_CASE:
                    mod_re = re.compile(self._config.REGEX, re.I)
                else:
                    mod_re = re.compile(self._config.REGEX)
            except re.error, e:
                debug.error('Error parsing regular expression: {0}'.format(e))
                
        # walk the modules list
        for module in modules.list_of_type("module", "list"):
            if self._config.REGEX:
                if not mod_re.search(str(module.name)):
                    continue
            yield module
            
    def render_text(self, outfd, data):
    
        if not self._config.DUMP_DIR:
            debug.error("You must supply a --dump-dir output directory")
        
        for module in data:
            ## TODO: pass module.name through a char sanitizer 
            file_name = "{0}.{1:#x}.lkm".format(module.name, module.module_core)
            mod_file = open(os.path.join(self._config.DUMP_DIR, file_name), 'wb')
            mod_data = self.addr_space.zread(module.module_core, module.core_size)
            mod_file.write(mod_data)
            mod_file.close()
            outfd.write("Wrote {0} bytes to {1}\n".format(module.core_size, file_name))
