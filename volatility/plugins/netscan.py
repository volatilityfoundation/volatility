# Volatility
#
# Authors:
# Michael Hale Ligh <michael.hale@gmail.com>
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
import volatility.plugins.common as common
import volatility.scan as scan
import volatility.obj as obj
import volatility.cache as cache
import volatility.debug as debug
import socket
import volatility.plugins.overlays.windows.tcpip_vtypes as tcpip_vtypes

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

class PoolScanUdpEndpoint(scan.PoolScanner):
    """PoolScanner for Udp Endpoints"""

    def object_offset(self, found, address_space):
        return found + (address_space.profile.get_obj_size("_POOL_HEADER") -
                        address_space.profile.get_obj_offset("_POOL_HEADER", "PoolTag"))

    checks = [ ('PoolTagCheck', dict(tag = "UdpA")),
               # Seen as 0xa8 on Vista SP0, 0xb0 on Vista SP2, and 0xb8 on 7
               # Seen as 0x150 on Win7 SP0 x64
               ('CheckPoolSize', dict(condition = lambda x: x >= 0xa8)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class PoolScanTcpListener(PoolScanUdpEndpoint):
    """PoolScanner for Tcp Listeners"""

    checks = [ ('PoolTagCheck', dict(tag = "TcpL")),
               # Seen as 0x120 on Win7 SP0 x64
               ('CheckPoolSize', dict(condition = lambda x: x >= 0xa8)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class PoolScanTcpEndpoint(PoolScanUdpEndpoint):
    """PoolScanner for TCP Endpoints"""

    checks = [ ('PoolTagCheck', dict(tag = "TcpE")),
               # Seen as 0x1f0 on Vista SP0, 0x1f8 on Vista SP2 and 0x210 on 7
               # Seen as 0x320 on Win7 SP0 x64
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x1f0)),
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

class Netscan(common.AbstractWindowsCommand):
    """Scan a Vista, 2008 or Windows 7 image for connections and sockets"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 6)

    @cache.CacheDecorator("tests/netscan")
    def calculate(self):

        # Virtual kernel space for dereferencing pointers
        kernel_space = utils.load_as(self._config)
        # Physical space for scanning 
        flat_space = utils.load_as(self._config, astype = 'physical')

        if not self.is_valid_profile(kernel_space.profile):
            debug.error("This command does not support the selected profile.")

        # Scan for TCP listeners also known as sockets
        for offset in PoolScanTcpListener().scan(flat_space):

            tcpentry = obj.Object('_TCP_LISTENER', offset = offset,
                                  vm = flat_space, native_vm = kernel_space)

            # Only accept IPv4 or IPv6
            if tcpentry.AddressFamily not in (AF_INET, AF_INET6):
                continue

            # For TcpL, the state is always listening and the remote port is zero
            for ver, laddr, raddr in tcpentry.dual_stack_sockets():
                yield tcpentry, "TCP" + ver, laddr, tcpentry.Port, raddr, 0, "LISTENING"

        # Scan for TCP endpoints also known as connections 
        for offset in PoolScanTcpEndpoint().scan(flat_space):

            tcpentry = obj.Object('_TCP_ENDPOINT', offset = offset,
                                  vm = flat_space, native_vm = kernel_space)

            if tcpentry.AddressFamily == AF_INET:
                proto = "TCPv4"
            elif tcpentry.AddressFamily == AF_INET6:
                proto = "TCPv6"
            else:
                continue

            # These are our sanity checks 
            if (tcpentry.State.v() not in tcpip_vtypes.TCP_STATE_ENUM or
                    (not tcpentry.LocalAddress and (not tcpentry.Owner or
                    tcpentry.Owner.UniqueProcessId == 0 or
                    tcpentry.Owner.UniqueProcessId > 65535))):
                continue

            yield tcpentry, proto, tcpentry.LocalAddress, tcpentry.LocalPort, \
                    tcpentry.RemoteAddress, tcpentry.RemotePort, tcpentry.State

        # Scan for UDP endpoints 
        for offset in PoolScanUdpEndpoint().scan(flat_space):

            udpentry = obj.Object('_UDP_ENDPOINT', offset = offset,
                                  vm = flat_space, native_vm = kernel_space)

            # Only accept IPv4 or IPv6
            if udpentry.AddressFamily not in (AF_INET, AF_INET6):
                continue

            # For UdpA, the state is always blank and the remote end is asterisks
            for ver, laddr, _ in udpentry.dual_stack_sockets():
                yield udpentry, "UDP" + ver, laddr, udpentry.Port, "*", "*", ""

    def render_text(self, outfd, data):

        outfd.write("{0:<10} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
            "Offset(P)", "Proto", "Local Address", "Foreign Address",
            "State", "Pid", "Owner", "Created"))

        for net_object, proto, laddr, lport, raddr, rport, state in data:

            lendpoint = "{0}:{1}".format(laddr, lport)
            rendpoint = "{0}:{1}".format(raddr, rport)

            outfd.write("{0:<#10x} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
                net_object.obj_offset, proto, lendpoint,
                rendpoint, state, net_object.Owner.UniqueProcessId,
                net_object.Owner.ImageFileName,
                str(net_object.CreateTime or '')
                ))

