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
import itertools

tcp_states = [
    "", # This must be empty, so the first enum starts at 1
    "CLOSED",
    "LISTENING",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB",
]

# Python's socket.AF_INET6 is 0x1e but MSFT's is 0x17..and we need to use MSFT's
AF_INET = 2
AF_INET6 = 0x17

# Compensate for Windows python not supporting socket.inet_ntop and some
# Linux systems (i.e. OpenSuSE 11.2 w/ Python 2.6) not supporting IPv6. 

def inet_ntop(address_family, packed_ip):

    def inet_ntop4(packed_ip):
        if not isinstance(packed_ip, str):
            raise TypeError("must be string, not {0}".format(type(packed_ip)))
        if len(packed_ip) != 4:
            raise ValueError("invalid length of packed IP address string")
        return "{0}.{1}.{2}.{3}".format(*[ord(x) for x in packed_ip])

    def inet_ntop6(packed_ip):
        if not isinstance(packed_ip, str):
            raise TypeError("must be string, not {0}".format(type(packed_ip)))
        if len(packed_ip) != 16:
            raise ValueError("invalid length of packed IP address string")

        words = []
        for i in range(0, 16, 2):
            words.append((ord(packed_ip[i]) << 8) | ord(packed_ip[i + 1]))

        # Replace a run of 0x00s with None
        numlen = [(k, len(list(g))) for k, g in itertools.groupby(words)]
        max_zero_run = sorted(sorted(numlen, key = lambda x: x[1], reverse = True), key = lambda x: x[0])[0]
        words = []
        for k, l in numlen:
            if (k == 0) and (l == max_zero_run[1]) and not (None in words):
                words.append(None)
            else:
                for i in range(l):
                    words.append(k)

        # Handle encapsulated IPv4 addresses
        encapsulated = ""
        if (words[0] is None) and (len(words) == 3 or (len(words) == 4 and words[1] == 0xffff)):
            words = words[:-2]
            encapsulated = inet_ntop4(packed_ip[-4:])
        # If we start or end with None, then add an additional :
        if words[0] is None:
            words = [None] + words
        if words[-1] is None:
            words += [None]
        # Join up everything we've got using :s
        return ":".join(["{0:x}".format(w) if w is not None else "" for w in words]) + encapsulated

    if address_family == socket.AF_INET:
        return inet_ntop4(packed_ip)
    elif address_family == socket.AF_INET6:
        return inet_ntop6(packed_ip)
    raise socket.error("[Errno 97] Address family not supported by protocol")

# String representations of INADDR_ANY and INADDR6_ANY
inaddr_any = inet_ntop(socket.AF_INET, '\0' * 4)
inaddr6_any = inet_ntop(socket.AF_INET6, '\0' * 16)

class PoolScanUdpEndpoint(scan.PoolScanner):
    """PoolScanner for Udp Endpoints"""
    checks = [ ('PoolTagCheck', dict(tag = "UdpA")),
               # Seen as 0xa8 on Vista SP0, 0xb0 on Vista SP2, and 0xb8 on 7
               ('CheckPoolSize', dict(condition = lambda x: x >= 0xa8)),
               ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class PoolScanTcpListener(scan.PoolScanner):
    """PoolScanner for Tcp Listeners"""
    checks = [ ('PoolTagCheck', dict(tag = "TcpL")),
               ('CheckPoolSize', dict(condition = lambda x: x == 0xa8)),
               ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

#class PoolScanRawEndpoint(scan.PoolScanner):
#    """PoolScanner for Raw Endpoints"""
#    checks = [ ('PoolTagCheck', dict(tag = "RawE")),
#               ('CheckPoolSize', dict(condition = lambda x: x == 0x90)),
#               ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
#               ('CheckPoolIndex', dict(value = 0)),
#               ]

class PoolScanTcpEndpoint(scan.PoolScanner):
    """PoolScanner for TCP Endpoints"""
    checks = [ ('PoolTagCheck', dict(tag = "TcpE")),
               # Seen as 0x1f0 on Vista SP0, 0x1f8 on Vista SP2 and 0x210 on 7
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x1f0)),
               ('CheckPoolType', dict(non_paged = True, paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class Netscan(commands.command):
    """Scan a Vista, 2008 or Windows 7 image for connections and sockets"""

    def enumerate_listeners(self, theObject, vspace = None):
        """
        Enumerate the listening IPv4 and IPv6 information. If vspace is
        provided, then it is assumed that theObject is in physical space, in
        which case we convert into the virtual space for handling pointers.

        Unlike XP, where you needed to create two sockets (one for IPv4 and
        one for IPv4), starting with Vista, Windows supports dual-stack sockets
        (http://msdn.microsoft.com/en-us/library/bb513665.aspx) which allows one
        socket to be created that can use both protocols. This is why our plugin
        prints an IPv4 address for all IPv6 sockets, however its also possible
        to create an IPv6 only socket by calling setsockopt with IPV6_V6ONLY.
        """

        if vspace != None:
            LocalAddr = obj.Object('_LOCAL_ADDRESS', theObject.LocalAddr, vspace)
            InetAF = obj.Object('_INETAF', theObject.InetAF, vspace)
            Owner = obj.Object('_EPROCESS', theObject.Owner, vspace)
        else:
            LocalAddr = theObject.LocalAddr
            InetAF = theObject.InetAF
            Owner = theObject.Owner

        # We only handle IPv4 and IPv6 sockets at the moment
        if InetAF.AddressFamily != AF_INET and InetAF.AddressFamily != AF_INET6:
            raise StopIteration

        if LocalAddr != None:
            inaddr = LocalAddr.pData.dereference().dereference().v()
            if InetAF.AddressFamily == AF_INET:
                laddr = inet_ntop(socket.AF_INET, vspace.zread(inaddr, 4))
                yield "v4", laddr, inaddr_any, Owner
            else:
                laddr = inet_ntop(socket.AF_INET6, vspace.zread(inaddr, 16))
                yield "v6", laddr, inaddr6_any, Owner
        else:
            yield "v4", inaddr_any, inaddr_any, Owner
            if InetAF.AddressFamily == AF_INET6:
                yield "v6", inaddr6_any, inaddr6_any, Owner

    @cache.CacheDecorator("tests/netscan")
    def calculate(self):
        vspace = utils.load_as(self._config)
        pspace = utils.load_as(self._config, astype = 'physical')

        for offset in PoolScanTcpListener().scan(pspace):
            tcpentry = obj.Object('_TCP_LISTENER', offset, pspace)

            lport = socket.ntohs(tcpentry.Port)

            # For TcpL, the state is always listening and the remote port is zero
            state = "LISTENING"
            rport = 0

            for ver, laddr, raddr, owner in self.enumerate_listeners(tcpentry, vspace):
                yield tcpentry.obj_offset, "TCP" + ver, laddr, lport, \
                    raddr, rport, state, owner, tcpentry.CreateTime

        for offset in PoolScanTcpEndpoint().scan(pspace):
            tcpentry = obj.Object('_TCP_ENDPOINT', offset, pspace)
            AddrInfo = obj.Object('_ADDRINFO', tcpentry.AddrInfo, vspace)
            InetAF = obj.Object('_INETAF', tcpentry.InetAF, vspace)
            Owner = obj.Object('_EPROCESS', tcpentry.Owner, vspace)

            lport = socket.ntohs(tcpentry.LocalPort)
            rport = socket.ntohs(tcpentry.RemotePort)

            try:
                state = tcp_states[tcpentry.State + 1]
            except IndexError:
                state = hex(tcpentry.State)

            l_inaddr = AddrInfo.Local.pData.dereference().dereference().v()
            r_inaddr = AddrInfo.Remote.dereference().v()

            if InetAF.AddressFamily == AF_INET:
                proto = "TCPv4"
                laddr = inet_ntop(socket.AF_INET, vspace.zread(l_inaddr, 4))
                raddr = inet_ntop(socket.AF_INET, vspace.zread(r_inaddr, 4))
            elif InetAF.AddressFamily == AF_INET6:
                proto = "TCPv6"
                laddr = inet_ntop(socket.AF_INET6, vspace.zread(l_inaddr, 16))
                raddr = inet_ntop(socket.AF_INET6, vspace.zread(r_inaddr, 16))
            else:
                continue

            yield tcpentry.obj_offset, proto, laddr, lport, raddr, \
                rport, state, Owner, tcpentry.CreateTime

        for offset in PoolScanUdpEndpoint().scan(pspace):
            udpentry = obj.Object('_UDP_ENDPOINT', offset, pspace)

            lport = socket.ntohs(udpentry.Port)

            # For UdpA, the state is always blank and the remote end is asterisks
            state = ""
            raddr = rport = "*"

            for ver, laddr, _, owner in self.enumerate_listeners(udpentry, vspace):
                yield udpentry.obj_offset, "UDP" + ver, laddr, lport, \
                    raddr, rport, state, owner, udpentry.CreateTime

    def render_text(self, outfd, data):
        outfd.write("{0:<10} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
            "Offset", "Proto", "Local Address", "Foreign Address", "State", "Pid", "Owner", "Created"))

        for offset, proto, laddr, lport, raddr, rport, state, p, ctime in data:
            lendpoint = "{0}:{1}".format(laddr, lport)
            rendpoint = "{0}:{1}".format(raddr, rport)
            process = p.ImageFileName if p.UniqueProcessId < 0xFFFF else ""
            outfd.write("{0:<#10x} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
                offset, proto, lendpoint, rendpoint, state, p.UniqueProcessId, process, ctime if ctime.v() else ""))

