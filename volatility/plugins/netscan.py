# Volatility
#
# Authors:
# Michael Hale Ligh <michael.hale@gmail.com>
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

import volatility.utils as utils
import volatility.plugins.common as common
import volatility.obj as obj
import volatility.cache as cache
import volatility.debug as debug
import volatility.poolscan as poolscan
import socket
import volatility.plugins.overlays.windows.tcpip_vtypes as tcpip_vtypes
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

# Python's socket.AF_INET6 is 0x1e but Microsoft defines it 
# as a constant value of 0x17 in their source code. Thus we 
# need Microsoft's since that's what is found in memory.
AF_INET = 2
AF_INET6 = 0x17

# String representations of INADDR_ANY and INADDR6_ANY
inaddr_any = utils.inet_ntop(socket.AF_INET, '\0' * 4)
inaddr6_any = utils.inet_ntop(socket.AF_INET6, '\0' * 16)

#--------------------------------------------------------------------------------
# pool scanners 
#--------------------------------------------------------------------------------

class PoolScanUdpEndpoint(poolscan.PoolScanner):
    """PoolScanner for Udp Endpoints"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.pooltag = "UdpA"
        self.struct_name = "_UDP_ENDPOINT"

        self.checks = [('CheckPoolSize', dict(condition = lambda x: x >= 0xa8)),
                   ('CheckPoolType', dict(non_paged = True, free = True)),
                   ('CheckPoolIndex', dict(value = 0)),
                   ]

class PoolScanTcpListener(poolscan.PoolScanner):
    """PoolScanner for Tcp Listeners"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.pooltag = "TcpL"
        self.struct_name = "_TCP_LISTENER"

        self.checks = [('CheckPoolSize', dict(condition = lambda x: x >= 0xa8)),
                   ('CheckPoolType', dict(non_paged = True, free = True)),
                   ('CheckPoolIndex', dict(value = 0)),
                   ]

class PoolScanTcpEndpoint(poolscan.PoolScanner):
    """PoolScanner for TCP Endpoints"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.pooltag = "TcpE"
        self.struct_name = "_TCP_ENDPOINT"

        self.checks = [('CheckPoolSize', dict(condition = lambda x: x >= 0x1f0)),
                   ('CheckPoolType', dict(non_paged = True, free = True)),
                   ('CheckPoolIndex', dict(value = 0)),
                   ]

#--------------------------------------------------------------------------------
# object classes 
#--------------------------------------------------------------------------------

class _TCP_LISTENER(obj.CType):
    """Class for objects found in TcpL pools"""

    @property
    def AddressFamily(self):
        return self.InetAF.dereference().AddressFamily

    @property
    def Owner(self):
        return self.m('Owner').dereference()

    def dual_stack_sockets(self):
        """Handle Windows dual-stack sockets"""

        # If this pointer is valid, the socket is bound to 
        # a specific IP address. Otherwise, the socket is 
        # listening on all IP addresses of the address family. 
        local_addr = self.LocalAddr.dereference()

        # Note the remote address is always INADDR_ANY or 
        # INADDR6_ANY for sockets. The moment a client 
        # connects to the listener, a TCP_ENDPOINT is created
        # and that structure contains the remote address.
        if local_addr != None:
            inaddr = local_addr.pData.dereference().dereference()
            if self.AddressFamily == AF_INET:
                yield "v4", inaddr.addr4, inaddr_any
            else:
                yield "v6", inaddr.addr6, inaddr6_any
        else:
            yield "v4", inaddr_any, inaddr_any
            if self.AddressFamily == AF_INET6:
                yield "v6", inaddr6_any, inaddr6_any

    def is_valid(self):
        return obj.CType.is_valid(self) and self.AddressFamily in (AF_INET, AF_INET6)

class _TCP_ENDPOINT(_TCP_LISTENER):
    """Class for objects found in TcpE pools"""

    def _ipv4_or_ipv6(self, in_addr):

        if self.AddressFamily == AF_INET:
            return in_addr.addr4
        else:
            return in_addr.addr6

    @property
    def LocalAddress(self):
        inaddr = self.AddrInfo.dereference().Local.\
                            pData.dereference().dereference()

        return self._ipv4_or_ipv6(inaddr)

    @property
    def RemoteAddress(self):
        inaddr = self.AddrInfo.dereference().\
                            Remote.dereference()

        return self._ipv4_or_ipv6(inaddr)

    def is_valid(self):
        if not obj.CType.is_valid(self):
            return False
  
        if self.AddressFamily not in (AF_INET, AF_INET6):
            return False
 
        if (self.State.v() not in tcpip_vtypes.TCP_STATE_ENUM or
                    (not self.LocalAddress and (not self.Owner or
                    self.Owner.UniqueProcessId == 0 or
                    self.Owner.UniqueProcessId > 65535))):
            return False

        return True

class _UDP_ENDPOINT(_TCP_LISTENER):
    """Class for objects found in UdpA pools"""

#--------------------------------------------------------------------------------
# profile modifications 
#--------------------------------------------------------------------------------

class NetscanObjectClasses(obj.ProfileModification):
    """Network OCs for Vista, 2008, and 7 x86 and x64"""

    before = ['WindowsObjectClasses']

    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x >= 0}

    def modification(self, profile):
        profile.object_classes.update({
            '_TCP_LISTENER': _TCP_LISTENER,
            '_TCP_ENDPOINT': _TCP_ENDPOINT,
            '_UDP_ENDPOINT': _UDP_ENDPOINT,
            })

#--------------------------------------------------------------------------------
# netscan plugin 
#--------------------------------------------------------------------------------

class Netscan(common.AbstractScanCommand):
    """Scan a Vista (or later) image for connections and sockets"""

    scanners = [PoolScanUdpEndpoint, PoolScanTcpListener, PoolScanTcpEndpoint]

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 6)

    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")

        for objct in self.scan_results(addr_space):

            if isinstance(objct, _UDP_ENDPOINT):
                # For UdpA, the state is always blank and the remote end is asterisks
                for ver, laddr, _ in objct.dual_stack_sockets():
                    yield objct, "UDP" + ver, laddr, objct.Port, "*", "*", ""
            elif isinstance(objct, _TCP_ENDPOINT):

                if objct.AddressFamily == AF_INET:
                    proto = "TCPv4"
                elif objct.AddressFamily == AF_INET6:
                    proto = "TCPv6"

                yield objct, proto, objct.LocalAddress, objct.LocalPort, \
                    objct.RemoteAddress, objct.RemotePort, objct.State
            elif isinstance(objct, _TCP_LISTENER):
                # For TcpL, the state is always listening and the remote port is zero
                for ver, laddr, raddr in objct.dual_stack_sockets():
                    yield objct, "TCP" + ver, laddr, objct.Port, raddr, 0, "LISTENING"

    def unified_output(self, data):
        return TreeGrid([(self.offset_column(), Address),
                       ("Proto", str),
                       ("LocalAddr", str),
                       ("ForeignAddr", str),
                       ("State", str),
                       ("PID", int),
                       ("Owner", str),
                       ("Created", str)],
                        self.generator(data))

    def generator(self, data):
        for net_object, proto, laddr, lport, raddr, rport, state in data:

            lendpoint = "{0}:{1}".format(laddr, lport)
            rendpoint = "{0}:{1}".format(raddr, rport)
            pid = -1
            owner = ""
            if net_object.Owner != None:
                pid = int(net_object.Owner.UniqueProcessId)
                owner = str(net_object.Owner.ImageFileName)

            yield (0, 
                [Address(net_object.obj_offset), 
                str(proto), 
                lendpoint,
                rendpoint, 
                str(state), 
                pid,
                owner,
                str(net_object.CreateTime or '')])

    def render_text(self, outfd, data):
        outfd.write("{0:<18} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
            self.offset_column(), "Proto", "Local Address", "Foreign Address",
            "State", "Pid", "Owner", "Created"))

        for net_object, proto, laddr, lport, raddr, rport, state in data:
            lendpoint = "{0}:{1}".format(laddr, lport)
            rendpoint = "{0}:{1}".format(raddr, rport)
            pid = -1
            owner = ""
            if net_object.Owner != None:
                pid = int(net_object.Owner.UniqueProcessId)
                owner = str(net_object.Owner.ImageFileName)

            outfd.write("{0:<#18x} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
                net_object.obj_offset, proto, lendpoint,
                rendpoint, state, pid,
                owner,
                str(net_object.CreateTime or '')
                ))
