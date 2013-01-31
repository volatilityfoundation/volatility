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

import volatility.commands as commands
import volatility.utils as utils
import volatility.obj as obj

def set_plugin_members(obj_ref):
    obj_ref.addr_space = utils.load_as(obj_ref._config)

class AbstractMacCommand(commands.command):
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
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'mac'

    def get_profile_symbol(self, sym_name, nm_type = "", sym_type = "", module = "kernel"):
        '''
        Gets a symbol out of the profile
        syn_name -> name of the symbol
        nm_tyes  -> types as defined by 'nm' (man nm for examples)
        sym_type -> the type of the symbol (passing Pointer will provide auto deref)
        module   -> which module to get the symbol from, default is kernel, otherwise can be any name seen in 'lsmod'

        Just a wrapper for AbstractLinuxProfile.get_symbol
        '''
        return self.profile.get_symbol(sym_name, nm_type, sym_type, module)

def is_known_address(handler, kernel_symbol_addresses, kmods, printme = 0):
    # see if this handler is in a known location
    good = 0 

    handler = handler.v()

    if handler in kernel_symbol_addresses:
        if printme:
            print " in kernel ",
        good = 1     
    else:
        # see if the address fits in any of the known modules
        for (start, end, name) in kmods:
            if start <= handler <= end:
                if printme:
                    print " in module %s ".format(name),
                good = 1
                break

    return good

def get_kernel_addrs(obj_ref):
    import volatility.plugins.mac.lsmod as lsmod
    # all the known addresses in the kernel
    # TODO -- make more stringent and get only symbols from .text
    kernel_symbol_addresses = obj_ref.profile.get_all_addresses()
    
    # module addresses, tuple of (start, end)
    # TODO -- make sure more stringent and parse each kext in-memory so we only allow whitelist from .text
    kmods = [(kmod.address, kmod.address + kmod.m('size'), kmod.name) for kmod in lsmod.mac_lsmod(obj_ref._config).calculate()] 

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



