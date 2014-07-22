# Volatility
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

import volatility.obj as obj

# Structures used by connections, connscan, sockets, sockscan.
# Used by x86 XP (all service packs) and x86 2003 SP0. 
tcpip_vtypes = {
    '_ADDRESS_OBJECT' : [ 0x68, {
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]],
    'LocalIpAddress' : [ 0x2c, ['IpAddress']],
    'LocalPort' : [ 0x30, ['unsigned be short']],
    'Protocol'  : [ 0x32, ['unsigned short']],
    'Pid' : [ 0x148, ['unsigned long']],
    'CreateTime' : [ 0x158, ['WinTimeStamp', dict(is_utc = True)]],
  }],
    '_TCPT_OBJECT' : [ 0x20, {
    'Next' : [ 0x0, ['pointer', ['_TCPT_OBJECT']]],
    'RemoteIpAddress' : [ 0xc, ['IpAddress']],
    'LocalIpAddress' : [ 0x10, ['IpAddress']],
    'RemotePort' : [ 0x14, ['unsigned be short']],
    'LocalPort' : [ 0x16, ['unsigned be short']],
    'Pid' : [ 0x18, ['unsigned long']],
    }],
}

# Structures used by connections, connscan, sockets, sockscan.
# Used by x64 XP and x64 2003 (all service packs). 
tcpip_vtypes_2003_x64 = {
    '_ADDRESS_OBJECT' : [ None, {
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]],
    'LocalIpAddress' : [ 0x58, ['IpAddress']], 
    'LocalPort' : [ 0x5c, ['unsigned be short']], 
    'Protocol'  : [ 0x5e, ['unsigned short']], 
    'Pid' : [ 0x238, ['unsigned long']], 
    'CreateTime' : [ 0x248, ['WinTimeStamp', dict(is_utc = True)]],
  }],
    '_TCPT_OBJECT' : [ None, {
    'Next' : [ 0x0, ['pointer', ['_TCPT_OBJECT']]],
    'RemoteIpAddress' : [ 0x14, ['IpAddress']], 
    'LocalIpAddress' : [ 0x18, ['IpAddress']], 
    'RemotePort' : [ 0x1c, ['unsigned be short']], 
    'LocalPort' : [ 0x1e, ['unsigned be short']], 
    'Pid' : [ 0x20, ['unsigned long']], 
    }],
}

# Structures used by sockets and sockscan.
# Used by x86 2003 SP1 and SP2 only. 
tcpip_vtypes_2003_sp1_sp2 = {
    '_ADDRESS_OBJECT' : [ 0x68, {
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]],
    'LocalIpAddress' : [ 0x30, ['IpAddress']],
    'LocalPort' : [ 0x34, ['unsigned be short']],
    'Protocol'  : [ 0x36, ['unsigned short']],
    'Pid' : [ 0x14C, ['unsigned long']],
    'CreateTime' : [ 0x158, ['WinTimeStamp', dict(is_utc = True)]],
    }],
}

TCP_STATE_ENUM = {
    0: 'CLOSED', 1: 'LISTENING', 2: 'SYN_SENT', 
    3: 'SYN_RCVD', 4: 'ESTABLISHED', 5: 'FIN_WAIT1', 
    6: 'FIN_WAIT2', 7: 'CLOSE_WAIT', 8: 'CLOSING', 
    9: 'LAST_ACK', 12: 'TIME_WAIT', 13: 'DELETE_TCB'
}

# Structures used by netscan for x86 Vista and 2008 (all service packs). 
tcpip_vtypes_vista = {
    '_IN_ADDR' : [ None, {
    'addr4' : [ 0x0, ['IpAddress']],
    'addr6' : [ 0x0, ['Ipv6Address']],
    }],
    '_LOCAL_ADDRESS' : [ None, {
    'pData' : [ 0xC, ['pointer', ['pointer', ['_IN_ADDR']]]],
    }],
    '_TCP_LISTENER': [ None, { # TcpL
    'Owner' : [ 0x18, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0x20, ['WinTimeStamp', dict(is_utc = True)]],
    'LocalAddr' : [ 0x34, ['pointer', ['_LOCAL_ADDRESS']]],
    'InetAF' : [ 0x38, ['pointer', ['_INETAF']]],
    'Port' : [ 0x3E, ['unsigned be short']],
    }],
    '_TCP_ENDPOINT': [ None, { # TcpE
    'InetAF' : [ 0xC, ['pointer', ['_INETAF']]],
    'AddrInfo' : [ 0x10, ['pointer', ['_ADDRINFO']]],
    'ListEntry': [ 0x14, ['_LIST_ENTRY']], 
    'State' : [ 0x28, ['Enumeration', dict(target = 'long', choices = TCP_STATE_ENUM)]],
    'LocalPort' : [ 0x2C, ['unsigned be short']],
    'RemotePort' : [ 0x2E, ['unsigned be short']],
    'Owner' : [ 0x160, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0, ['WinTimeStamp', dict(value = 0, is_utc = True)]],
    }],
    '_TCP_SYN_ENDPOINT': [ None, {
    'ListEntry': [ 8, ['_LIST_ENTRY']], 
    'InetAF' : [ 0x18, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x3c, ['unsigned be short']],
    'RemotePort' : [ 0x3e, ['unsigned be short']],
    'LocalAddr' : [ 0x1c, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x28, ['pointer', ['_IN_ADDR']]],
    'Owner' : [ 0x20, ['pointer', ['_SYN_OWNER']]],
    'CreateTime' : [ 0, ['WinTimeStamp', dict(value = 0, is_utc = True)]],
    }], 
    '_SYN_OWNER': [ None, {
    'Process': [ 0x18, ['pointer', ['_EPROCESS']]], 
    }], 
    '_TCP_TIMEWAIT_ENDPOINT': [ None, {
    'ListEntry': [ 0x14, ['_LIST_ENTRY']], 
    'InetAF' : [ 0xc, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x1c, ['unsigned be short']],
    'RemotePort' : [ 0x1e, ['unsigned be short']],
    'LocalAddr' : [ 0x20, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x24, ['pointer', ['_IN_ADDR']]],
    'CreateTime' : [ 0, ['WinTimeStamp', dict(value = 0, is_utc = True)]],
    }], 
    '_INETAF' : [ None, {
    'AddressFamily' : [ 0xC, ['unsigned short']],
    }],
    '_ADDRINFO' : [ None, {
    'Local' : [ 0x0, ['pointer', ['_LOCAL_ADDRESS']]],
    'Remote' : [ 0x8, ['pointer', ['_IN_ADDR']]],
    }],
    '_UDP_ENDPOINT': [ None, { # UdpA
    'Owner' : [ 0x18, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0x30, ['WinTimeStamp', dict(is_utc = True)]],
    'LocalAddr' : [ 0x38, ['pointer', ['_LOCAL_ADDRESS']]],
    'InetAF' : [ 0x14, ['pointer', ['_INETAF']]],
    'Port' : [ 0x48, ['unsigned be short']],
    }],
}

# Structures for netscan on x86 Windows 7 (all service packs).
tcpip_vtypes_7 = {
    '_TCP_ENDPOINT': [ None, { # TcpE
    'InetAF' : [ 0xC, ['pointer', ['_INETAF']]],
    'AddrInfo' : [ 0x10, ['pointer', ['_ADDRINFO']]],
    'ListEntry': [ 0x14, ['_LIST_ENTRY']], 
    'State' : [ 0x34, ['Enumeration', dict(target = 'long', choices = TCP_STATE_ENUM)]],
    'LocalPort' : [ 0x38, ['unsigned be short']],
    'RemotePort' : [ 0x3A, ['unsigned be short']],
    'Owner' : [ 0x174, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0, ['WinTimeStamp', dict(value = 0, is_utc = True)]],
    }],
    '_TCP_SYN_ENDPOINT': [ None, {
    'ListEntry': [ 8, ['_LIST_ENTRY']], 
    'InetAF' : [ 0x24, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x48, ['unsigned be short']],
    'RemotePort' : [ 0x4a, ['unsigned be short']],
    'LocalAddr' : [ 0x28, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x34, ['pointer', ['_IN_ADDR']]],
    'Owner' : [ 0x2c, ['pointer', ['_SYN_OWNER']]],
    'CreateTime' : [ 0, ['WinTimeStamp', dict(value = 0, is_utc = True)]],
    }], 
    '_TCP_TIMEWAIT_ENDPOINT': [ None, {
    'ListEntry': [ 0, ['_LIST_ENTRY']], 
    'InetAF' : [ 0x18, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x28, ['unsigned be short']],
    'RemotePort' : [ 0x2a, ['unsigned be short']],
    'LocalAddr' : [ 0x2c, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x30, ['pointer', ['_IN_ADDR']]],
    'CreateTime' : [ 0, ['WinTimeStamp', dict(value = 0, is_utc = True)]],
    }], 
}

# Structures for netscan on x64 Vista SP0 and 2008 SP0
tcpip_vtypes_vista_64 = {
    '_IN_ADDR' : [ None, {
    'addr4' : [ 0x0, ['IpAddress']],
    'addr6' : [ 0x0, ['Ipv6Address']],
    }],
    '_TCP_LISTENER': [ None, { # TcpL
    'Owner' : [ 0x28, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0x20, ['WinTimeStamp', dict(is_utc = True)]],
    'LocalAddr' : [ 0x58, ['pointer', ['_LOCAL_ADDRESS']]],
    'InetAF' : [ 0x60, ['pointer', ['_INETAF']]],
    'Port' : [ 0x6a, ['unsigned be short']],
    }],
    '_INETAF' : [ None, {
    'AddressFamily' : [ 0x14, ['unsigned short']],
    }],
    '_LOCAL_ADDRESS' : [ None, {
    'pData' : [ 0x10, ['pointer', ['pointer', ['_IN_ADDR']]]],
    }],
    '_ADDRINFO' : [ None, {
    'Local' : [ 0x0, ['pointer', ['_LOCAL_ADDRESS']]],
    'Remote' : [ 0x10, ['pointer', ['_IN_ADDR']]],
    }],
    '_TCP_ENDPOINT': [ None, { # TcpE
    'InetAF' : [ 0x18, ['pointer', ['_INETAF']]],
    'AddrInfo' : [ 0x20, ['pointer', ['_ADDRINFO']]],
    'ListEntry': [ 0x28, ['_LIST_ENTRY']], 
    'State' : [ 0x50, ['Enumeration', dict(target = 'long', choices = TCP_STATE_ENUM)]],
    'LocalPort' : [ 0x54, ['unsigned be short']],
    'RemotePort' : [ 0x56, ['unsigned be short']],
    'Owner' : [ 0x208, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0, ['WinTimeStamp', dict(value = 0, is_utc = True)]],
    }],
    '_TCP_SYN_ENDPOINT': [ None, {
    'ListEntry': [ 0x10, ['_LIST_ENTRY']], 
    'InetAF' : [ 0x30, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x64, ['unsigned be short']],
    'RemotePort' : [ 0x66, ['unsigned be short']],
    'LocalAddr' : [ 0x38, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x50, ['pointer', ['_IN_ADDR']]],
    'Owner' : [ 0x40, ['pointer', ['_SYN_OWNER']]],
    'CreateTime' : [ 0, ['WinTimeStamp', dict(value = 0, is_utc = True)]],
    }], 
    '_SYN_OWNER': [ None, {
    'Process': [ 0x28, ['pointer', ['_EPROCESS']]], 
    }], 
    '_TCP_TIMEWAIT_ENDPOINT': [ None, {
    'ListEntry': [ 0, ['_LIST_ENTRY']], 
    'InetAF' : [ 0x18, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x30, ['unsigned be short']],
    'RemotePort' : [ 0x32, ['unsigned be short']],
    'LocalAddr' : [ 0x38, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x40, ['pointer', ['_IN_ADDR']]],
    'CreateTime' : [ 0, ['WinTimeStamp', dict(value = 0, is_utc = True)]],
    }], 
    '_UDP_ENDPOINT': [ None, { # UdpA
    'Owner' : [ 0x28, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0x58, ['WinTimeStamp', dict(is_utc = True)]],
    'LocalAddr' : [ 0x60, ['pointer', ['_LOCAL_ADDRESS']]],
    'InetAF' : [ 0x20, ['pointer', ['_INETAF']]],
    'Port' : [ 0x80, ['unsigned be short']],
    }],
}

class _ADDRESS_OBJECT(obj.CType):

    def is_valid(self):
        return obj.CType.is_valid(self) and self.CreateTime.v() > 0

class WinXP2003AddressObject(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x : x == 5}
    def modification(self, profile):
        profile.object_classes.update({'_ADDRESS_OBJECT': _ADDRESS_OBJECT})

class WinXP2003Tcpipx64(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 5,
                  'minor': lambda x : x == 2}
    def modification(self, profile):
        profile.vtypes.update(tcpip_vtypes_2003_x64)

class Win2003SP12Tcpip(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 5,
                  'minor': lambda x : x == 2,
                  'build': lambda x : x != 3789}
    def modification(self, profile):
        profile.vtypes.update(tcpip_vtypes_2003_sp1_sp2)

class Vista2008Tcpip(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x >= 0}
    def modification(self, profile):
        profile.vtypes.update(tcpip_vtypes_vista)

class Win7Tcpip(obj.ProfileModification):
    before = ['Vista2008Tcpip']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 1}
    def modification(self, profile):
        profile.vtypes.update(tcpip_vtypes_7)

class Win7Vista2008x64Tcpip(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x >= 0}
    def modification(self, profile):
        profile.vtypes.update(tcpip_vtypes_vista_64)

class VistaSP12x64Tcpip(obj.ProfileModification):
    before = ['Win7Vista2008x64Tcpip']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 0, 
                  'build': lambda x : x >= 6001}
    def modification(self, profile):
        profile.merge_overlay({
            '_TCP_ENDPOINT': [ None, {
                'Owner' : [ 0x210, ['pointer', ['_EPROCESS']]],
             }],
        })

class Win7x64Tcpip(obj.ProfileModification):
    before = ['Win7Vista2008x64Tcpip']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 1}
    def modification(self, profile):
        profile.merge_overlay({
            '_TCP_ENDPOINT': [ None, {
                'State' : [ 0x68, ['Enumeration', dict(target = 'long', choices = TCP_STATE_ENUM)]],
                'LocalPort' : [ 0x6c, ['unsigned be short']],
                'RemotePort' : [ 0x6e, ['unsigned be short']],
                'Owner' : [ 0x238, ['pointer', ['_EPROCESS']]],
                }],
            '_TCP_SYN_ENDPOINT': [ None, {
                'InetAF' : [ 0x48, ['pointer', ['_INETAF']]],
                'LocalPort' : [ 0x7c, ['unsigned be short']],
                'RemotePort' : [ 0x7e, ['unsigned be short']],
                'LocalAddr' : [ 0x50, ['pointer', ['_LOCAL_ADDRESS']]],
                'RemoteAddress' : [ 0x68, ['pointer', ['_IN_ADDR']]],
                'Owner' : [ 0x58, ['pointer', ['_SYN_OWNER']]],
                }], 
            '_TCP_TIMEWAIT_ENDPOINT': [ None, {
                'InetAF' : [ 0x30, ['pointer', ['_INETAF']]],
                'LocalPort' : [ 0x48, ['unsigned be short']],
                'RemotePort' : [ 0x4a, ['unsigned be short']],
                'LocalAddr' : [ 0x50, ['pointer', ['_LOCAL_ADDRESS']]],
                'RemoteAddress' : [ 0x58, ['pointer', ['_IN_ADDR']]],
                }], 
            })

class Win8Tcpip(obj.ProfileModification):
    before = ['Vista2008Tcpip']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x >= 2}
    def modification(self, profile):
        profile.merge_overlay({
        '_TCP_ENDPOINT': [ None, {
            'InetAF' : [ 0x8, ['pointer', ['_INETAF']]],
            'AddrInfo' : [ 0xC, ['pointer', ['_ADDRINFO']]],
            'State' : [ 0x38, ['Enumeration', dict(target = 'long', choices = TCP_STATE_ENUM)]],
            'LocalPort' : [ 0x3C, ['unsigned be short']],
            'RemotePort' : [ 0x3E, ['unsigned be short']],
            'Owner' : [ 0x174, ['pointer', ['_EPROCESS']]],
            }],
        })

class Win81Tcpip(obj.ProfileModification):
    before = ['Win8Tcpip']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 3}
    def modification(self, profile):
        profile.merge_overlay({
        '_TCP_ENDPOINT': [ None, {
            'Owner' : [ 0x1a8, ['pointer', ['_EPROCESS']]],
            }],
        })

class Win8x64Tcpip(obj.ProfileModification):
    before = ['Win7Vista2008x64Tcpip']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x >= 2}
    def modification(self, profile):
        profile.merge_overlay({
            '_INETAF' : [ None, {
                'AddressFamily' : [ 0x18, ['unsigned short']],
                }],
            '_TCP_ENDPOINT': [ None, {
                'InetAF' : [ 0x10, ['pointer', ['_INETAF']]],
                'AddrInfo' : [ 0x18, ['pointer', ['_ADDRINFO']]],
                'State' : [ 0x6C, ['Enumeration', dict(target = 'long', choices = TCP_STATE_ENUM)]],
                'LocalPort' : [ 0x70, ['unsigned be short']],
                'RemotePort' : [ 0x72, ['unsigned be short']],
                'Owner' : [ 0x250, ['pointer', ['_EPROCESS']]],
                }],
            })

class Win81x64Tcpip(obj.ProfileModification):
    before = ['Win8x64Tcpip']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 3}
    def modification(self, profile):
        profile.merge_overlay({
            '_TCP_ENDPOINT': [ None, {
                'Owner' : [ 0x258, ['pointer', ['_EPROCESS']]],
                }],
            })
