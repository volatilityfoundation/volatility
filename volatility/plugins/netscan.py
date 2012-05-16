# Volatility
#
# Authors:
# Michael Hale Ligh <michael.hale@gmail.com>
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
#

import volatility.utils as utils
import volatility.commands as commands
import volatility.scan as scan
import volatility.obj as obj
import volatility.cache as cache
import socket

# Python's socket.AF_INET6 is 0x1e but MSFT's is 0x17..and we need to use MSFT's
AF_INET = 2
AF_INET6 = 0x17

# String representations of INADDR_ANY and INADDR6_ANY
inaddr_any = utils.inet_ntop(socket.AF_INET, '\0' * 4)
inaddr6_any = utils.inet_ntop(socket.AF_INET6, '\0' * 16)

class PoolScanUdpEndpoint(scan.PoolScanner):
    """PoolScanner for Udp Endpoints"""

    def object_offset(self, found, address_space):
        return found + (address_space.profile.get_obj_size("_POOL_HEADER") -
                        address_space.profile.get_obj_offset("_POOL_HEADER", "PoolTag"))

    checks = [ ('PoolTagCheck', dict(tag = "UdpA")),
               # Seen as 0xa8 on Vista SP0, 0xb0 on Vista SP2, and 0xb8 on 7
               # Seen as 0x150 on Win7 SP0 x64
               ('CheckPoolSize', dict(condition = lambda x: x >= 0xa8)),
               ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class PoolScanTcpListener(PoolScanUdpEndpoint):
    """PoolScanner for Tcp Listeners"""

    checks = [ ('PoolTagCheck', dict(tag = "TcpL")),
               # Seen as 0x120 on Win7 SP0 x64
               ('CheckPoolSize', dict(condition = lambda x: x >= 0xa8)),
               ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class PoolScanTcpEndpoint(PoolScanUdpEndpoint):
    """PoolScanner for TCP Endpoints"""

    checks = [ ('PoolTagCheck', dict(tag = "TcpE")),
               # Seen as 0x1f0 on Vista SP0, 0x1f8 on Vista SP2 and 0x210 on 7
               # Seen as 0x320 on Win7 SP0 x64
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x1f0)),
               ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class Netscan(commands.Command):
    """Scan a Vista, 2008 or Windows 7 image for connections and sockets"""

    def enumerate_listeners(self, theObject):
        """
        Enumerate the listening IPv4 and IPv6 information. 

        Unlike XP, where you needed to create two sockets (one for IPv4 and
        one for IPv4), starting with Vista, Windows supports dual-stack sockets
        (http://msdn.microsoft.com/en-us/library/bb513665.aspx) which allows one
        socket to be created that can use both protocols. This is why our plugin
        prints an IPv4 address for all IPv6 sockets, however its also possible
        to create an IPv6 only socket by calling setsockopt with IPV6_V6ONLY.
        """

        # These pointers are dereferenced in kernel space since we set
        # native_vm when the objects were created. 
        LocalAddr = theObject.LocalAddr.dereference()
        InetAF = theObject.InetAF.dereference()
        Owner = theObject.Owner.dereference()

        # We only handle IPv4 and IPv6 sockets at the moment
        if InetAF.AddressFamily != AF_INET and InetAF.AddressFamily != AF_INET6:
            raise StopIteration

        if LocalAddr != None:
            inaddr = LocalAddr.pData.dereference().dereference()
            if InetAF.AddressFamily == AF_INET:
                laddr = inaddr.addr4
                yield "v4", laddr, inaddr_any, Owner
            else:
                laddr = inaddr.addr6
                yield "v6", laddr, inaddr6_any, Owner
        else:
            yield "v4", inaddr_any, inaddr_any, Owner
            if InetAF.AddressFamily == AF_INET6:
                yield "v6", inaddr6_any, inaddr6_any, Owner

    @cache.CacheDecorator("tests/netscan")
    def calculate(self):
        # Virtual kernel space for dereferencing pointers
        kernel_space = utils.load_as(self._config)
        # Physical space for scanning 
        flat_space = utils.load_as(self._config, astype = 'physical')

        for offset in PoolScanTcpListener().scan(flat_space):
            tcpentry = obj.Object('_TCP_LISTENER', offset = offset,
                                  vm = flat_space, native_vm = kernel_space)

            lport = tcpentry.Port

            # For TcpL, the state is always listening and the remote port is zero
            state = "LISTENING"
            rport = 0

            for ver, laddr, raddr, owner in self.enumerate_listeners(tcpentry):
                yield tcpentry.obj_offset, "TCP" + ver, laddr, lport, raddr, rport, state, owner, tcpentry.CreateTime

        for offset in PoolScanTcpEndpoint().scan(flat_space):
            tcpentry = obj.Object('_TCP_ENDPOINT', offset = offset,
                                  vm = flat_space, native_vm = kernel_space)

            # These pointers are dereferenced in kernel space since we set
            # native_vm when the objects were created. 
            AddrInfo = tcpentry.AddrInfo.dereference()
            InetAF = tcpentry.InetAF.dereference()
            Owner = tcpentry.Owner.dereference()

            lport = tcpentry.LocalPort
            rport = tcpentry.RemotePort
            state = tcpentry.State

            l_inaddr = AddrInfo.Local.pData.dereference().dereference()
            r_inaddr = AddrInfo.Remote.dereference()

            if InetAF.AddressFamily == AF_INET:
                proto = "TCPv4"
                laddr = l_inaddr.addr4
                raddr = r_inaddr.addr4
            elif InetAF.AddressFamily == AF_INET6:
                proto = "TCPv6"
                laddr = l_inaddr.addr6
                raddr = r_inaddr.addr6
            else:
                continue

            yield tcpentry.obj_offset, proto, laddr, lport, raddr, rport, state, Owner, tcpentry.CreateTime

        for offset in PoolScanUdpEndpoint().scan(flat_space):
            udpentry = obj.Object('_UDP_ENDPOINT', offset = offset,
                                  vm = flat_space, native_vm = kernel_space)

            lport = udpentry.Port

            # For UdpA, the state is always blank and the remote end is asterisks
            state = ""
            raddr = rport = "*"

            for ver, laddr, _, owner in self.enumerate_listeners(udpentry):
                yield udpentry.obj_offset, "UDP" + ver, laddr, lport, raddr, rport, state, owner, udpentry.CreateTime

    def render_text(self, outfd, data):
        outfd.write("{0:<10} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
            "Offset(P)", "Proto", "Local Address", "Foreign Address", "State", "Pid", "Owner", "Created"))

        for offset, proto, laddr, lport, raddr, rport, state, p, ctime in data:
            lendpoint = "{0}:{1}".format(laddr, lport)
            rendpoint = "{0}:{1}".format(raddr, rport)
            process = p.ImageFileName if p.UniqueProcessId < 0xFFFF else ""
            outfd.write("{0:<#10x} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
                offset, proto, lendpoint, rendpoint, state, p.UniqueProcessId, process, ctime if ctime.v() else ""))

