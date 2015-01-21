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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import os

import volatility.commands as commands
import volatility.utils as utils
import volatility.obj as obj

def set_plugin_members(obj_ref):
    obj_ref.addr_space = utils.load_as(obj_ref._config)

class AbstractMacCommand(commands.Command):
    def __init__(self, *args, **kwargs):
        self.addr_space = None
        commands.Command.__init__(self, *args, **kwargs)

    @property
    def profile(self):
        if self.addr_space:
            return self.addr_space.profile
        return None

    def execute(self, *args, **kwargs):
        commands.Command.execute(self, *args, **kwargs)

    @staticmethod
    def register_options(config):
        config.add_option("SHIFT", type = 'int', default = 0, help = "Mac KASLR shift address")

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'mac'

def is_in_kernel_or_module(handler, ktext_start, ktext_end, kmods):
    # see if this handler is in a known location
    good = 0 
    module = "UNKNOWN"

    if ktext_start <= handler <= ktext_end:
        good = 1     
        module = "__kernel__"
    elif kmods != []:
        # see if the address fits in any of the known modules
        for (start, end, name) in kmods:
            if start <= handler <= end:
                good = 1
                module = name
                break

    return (good, module)

def get_handler_name(kaddr_info, handler):
    (obj_ref, kernel_symbol_addresses, ktext_start, ktext_end, kmods) = kaddr_info

    module      = "UNKNOWN"
    handler_sym = ""

    if handler in kernel_symbol_addresses:
        module  = "__kernel__"
        handler_sym = obj_ref.profile.get_symbol_by_address("kernel", handler)

    elif ktext_start <= handler <= ktext_end:
        module = "__kernel__"
    
    elif kmods != []:
        # see if the address fits in any of the known modules
        for (start, end, name) in kmods:
            if start <= handler <= end:
                module = name
                break

    return (module, handler_sym)

def is_known_address_name(handler, kernel_symbol_addresses, kmods):
    # see if this handler is in a known location
    good = 0 
    module = "UNKNOWN"

    if handler in kernel_symbol_addresses:
        good = 1     
        module = "__kernel__"
    elif kmods != []:
        # see if the address fits in any of the known modules
        for (start, end, name) in kmods:
            if start <= handler <= end:
                good = 1
                module = name
                break

    return (good, module)

def is_64bit_capable(addr_space):
    """Test if the AS is capable of doing 64-bits. 

    @returns True if 64-bit capable. 
    """
    x86_64_flag_addr = addr_space.profile.get_symbol("_x86_64_flag")
    
    # this symbol no longer exists in 10.9 / Mavericks
    # this is most likely b/c all Macs are 64 bit by 10.9
    if x86_64_flag_addr:
        x86_64_flag = obj.Object("int", offset = x86_64_flag_addr, vm = addr_space)
        ret = x86_64_flag == 1
    else:
        ret = True

    return ret

def get_kernel_function_addrs(obj_ref):
    import volatility.plugins.mac.lsmod as lsmod
    
    kernel_symbol_addresses = obj_ref.profile.get_all_function_addresses()

   # TODO -- make sure more stringent and parse each kext in-memory so we only allow whitelist from .text
    kmods = [(kmod.address, kmod.address + kmod.m('size'), kmod.name) for kmod in lsmod.mac_lsmod(obj_ref._config).calculate() if str(kmod.name) != "com.apple.kpi.unsupported"] 

    return (kernel_symbol_addresses, kmods)

def get_kernel_addrs_start_end(obj_ref):
    import volatility.plugins.mac.lsmod as lsmod
   
    s = obj_ref.profile.get_symbol("_vm_kernel_stext")
    e = obj_ref.profile.get_symbol("_vm_kernel_etext") 

    if s == None:
        s = obj_ref.profile.get_symbol("_stext")
       
    if e == None:
        e = obj_ref.profile.get_symbol("_etext") 
    
    start = obj.Object("unsigned long", offset = s, vm = obj_ref.addr_space)
    end   = obj.Object("unsigned long", offset = e, vm = obj_ref.addr_space)

    # module addresses, tuple of (start, end)
    # TODO -- make sure more stringent and parse each kext in-memory so we only allow whitelist from .text
    kmods = [(kmod.address.v(), kmod.address.v() + kmod.m('size'), kmod.name) for kmod in lsmod.mac_lsmod(obj_ref._config).calculate() if str(kmod.name) != "com.apple.kpi.unsupported"] 

    return (start, end, kmods)

def get_handler_name_addrs(obj_ref):
    import volatility.plugins.mac.lsmod as lsmod
   
    s = obj_ref.profile.get_symbol("_vm_kernel_stext")
    e = obj_ref.profile.get_symbol("_vm_kernel_etext") 

    if s == None:
        s = obj_ref.profile.get_symbol("_stext")
       
    if e == None:
        e = obj_ref.profile.get_symbol("_etext") 
    
    start = obj.Object("unsigned long", offset = s, vm = obj_ref.addr_space)
    end   = obj.Object("unsigned long", offset = e, vm = obj_ref.addr_space)

    # module addresses, tuple of (start, end)
    # TODO -- make sure more stringent and parse each kext in-memory so we only allow whitelist from .text
    kmods = [(kmod.address.v(), kmod.address.v() + kmod.m('size'), kmod.name) for kmod in lsmod.mac_lsmod(obj_ref._config).calculate() if str(kmod.name) != "com.apple.kpi.unsupported"] 

    kernel_symbol_addresses = obj_ref.profile.get_all_function_addresses()
    
    return (obj_ref, kernel_symbol_addresses, start, end, kmods)

def get_kernel_addrs(obj_ref):
    import volatility.plugins.mac.lsmod as lsmod
    # all the known addresses in the kernel
    # TODO -- make more stringent and get only symbols from .text
    kernel_symbol_addresses = obj_ref.profile.get_all_addresses()
    
    # module addresses, tuple of (start, end)
    # TODO -- make sure more stringent and parse each kext in-memory so we only allow whitelist from .text
    kmods = [(kmod.address.v(), kmod.address.v() + kmod.m('size'), kmod.name) for kmod in lsmod.mac_lsmod(obj_ref._config).calculate() if str(kmod.name) != "com.apple.kpi.unsupported"] 

    return (kernel_symbol_addresses, kmods)

## FIXME: remove this function after all references from plugins are removed
def get_string(addr, addr_space, maxlen = 256):

    name = addr_space.read(addr, maxlen)
    ret = ""

    for n in name:
        if ord(n) == 0:
            break
        ret = ret + n 

    return ret 

# account for c++ symbol name mangling
def get_cpp_sym(name, profile):
    for (cppname, addr) in profile.get_all_symbols():
        if cppname.find(name) != -1:
            return addr

    return None

def write_vnode_to_file(vnode, file_path):
    fd = open(file_path, "wb")
    wrote = 0 

    for (offset, page) in vnode.get_contents():
        fd.seek(offset)
        fd.write(page) 
        wrote = wrote + len(page)            

    fd.close()

    return wrote

def write_macho_file(out_dir, proc, exe_address):
    exe_contents = proc.get_macho(exe_address)     
 
    file_name = "task.{0}.{1:#x}.dmp".format(proc.p_pid, exe_address)
    file_path = os.path.join(out_dir, file_name)

    outfile = open(file_path, "wb+")
    outfile.write(exe_contents)            
    outfile.close()

    return file_path


