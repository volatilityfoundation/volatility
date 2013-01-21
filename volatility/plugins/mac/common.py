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
import volatility.utils    as utils
import volatility.obj      as obj

import datetime

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

def is_known_address(handler, kernel_symbol_addresses, kmods, printme=0):

    # see if this handler is in a known location

    good = 0 

    if handler in kernel_symbol_addresses:
        if printme:
            print " in kernel ",
        good = 1     
    else:
    
        # see if the address fits in any of the known modules
        for (start, end, name) in kmods:
            
            if start <= handler <= end:
                if printme:
                    print " in module %s " % name,
                good = 1
                break

    return good

from lsmod import mac_lsmod as mac_lsmod

def get_kernel_addrs(self):
    # all the known addresses in the kernel
    # TODO -- make more stringent and get only symbols from .text
    kernel_symbol_addresses = [addrs[0] for addrs in self.profile.get_all_symbols()]
    
    # module addresses, tuple of (start, end)
    # TODO -- make sure more stringent and parse each kext in-memory so we only allow whitelist from .text
    kmods = [(kmod.address, kmod.address + kmod.m('size'), get_string(kmod.name.obj_offset, self.addr_space)) for kmod in mac_lsmod.calculate(self)] 

    return (kernel_symbol_addresses, kmods)

def get_ip(self, addr):

    dst = obj.Object("sockaddr", offset=addr, vm=self.addr_space)

    if dst.sa_family == 2: # AF_INET
    
        saddr = obj.Object("sockaddr_in", offset=addr, vm=self.addr_space)
    
        s = obj.Object(theType = 'Array', offset = saddr.sin_addr.v(), vm = self.addr_space, targetType = 'unsigned char', count = 4)

        ip = "%d.%d.%d.%d" % (s[0], s[1], s[2], s[3])

    elif dst.sa_family == 18:  # AF_LINK

        s = obj.Object("sockaddr_dl", offset=addr, vm=self.addr_space)

        if [s.sdl_nlen, s.sdl_alen, s.sdl_slen] == [0,0,0]:
            ip = "link%d" % s.sdl_index
        else:
            ip = ":".join(["%02x" % ord(x.v()) for x in s.sdl_data[s.sdl_nlen : s.sdl_nlen + s.sdl_alen]])  
            
    else:
        ip = "unknown"

    return ip

def print_rt(self, rt):

    src_ip = get_ip(self, rt.rt_nodes[0].rn_u.rn_leaf.rn_Key)
    dst_ip = get_ip(self, rt.rt_gateway)

    name = get_string(rt.rt_ifp.if_name, self.addr_space)

    unit = rt.rt_ifp.if_unit

    caltime = rt.base_calendartime
    prettytime = datetime.datetime.fromtimestamp(caltime).strftime('%Y-%m-%d %H:%M:%S')

    sent = rt.rt_stats.nstat_txpackets
    rx   = rt.rt_stats.nstat_rxpackets

    exp   = rt.rt_expire
    if exp == 0:
        delta = 0
    else:
        delta = exp - rt.base_uptime

    print "%s : %s - %s%d - %d - %d | %d %s | %d %d" % (src_ip, dst_ip, name, unit, sent, rx, caltime, prettytime, exp, delta) 


def get_string(addr, addr_space, maxlen = 256):

    name = addr_space.read(addr, maxlen)
    ret = ""

    for n in name:
        if ord(n) == 0:
            break
        ret = ret + n 

    return ret 

# account for c++ symbol name mangling
def get_cpp_sym(name, smap):

    for s in smap:
        if s.find(name) != -1:
            return smap[s]

    return None



