'''
Created on 31 Dec 2010

@author: mike
'''

tcpip_vtypes = {
  '_ADDRESS_OBJECT' : [ 0x68, {
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]],
    'LocalIpAddress' : [ 0x2c, ['IpAddress']],
    'LocalPort' : [ 0x30, ['unsigned short']],
    'Protocol'  : [ 0x32, ['unsigned short']],
    'Pid' : [ 0x148, ['unsigned long']],
    'CreateTime' : [ 0x158, ['_LARGE_INTEGER']],
} ],
  '_TCPT_OBJECT' : [ 0x20, {
  'Next' : [ 0x0, ['pointer', ['_TCPT_OBJECT']]],
  'RemoteIpAddress' : [ 0xc, ['IpAddress']],
  'LocalIpAddress' : [ 0x10, ['IpAddress']],
  'RemotePort' : [ 0x14, ['unsigned short']],
  'LocalPort' : [ 0x16, ['unsigned short']],
  'Pid' : [ 0x18, ['unsigned long']],
} ],
}

tcpip_vtypes_2k3_sp1_sp2 = {
  '_ADDRESS_OBJECT' : [ 0x68, {
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]],
    'LocalIpAddress' : [ 0x30, ['IpAddress']],
    'LocalPort' : [ 0x34, ['unsigned short']],
    'Protocol'  : [ 0x36, ['unsigned short']],
    'Pid' : [ 0x14C, ['unsigned long']],
    'CreateTime' : [ 0x158, ['_LARGE_INTEGER']],
} ],
}

tcpip_vtypes_vista = {
    '_IN_ADDR' : [ None, {
        'addr4' : [ 0x0, ['array', 4, ['unsigned char']]],
        'addr6' : [ 0x0, ['array', 16, ['unsigned char']]],
    } ],
    '_LOCAL_ADDRESS' : [ None, {
        'pData' : [ 0xC, ['pointer', ['pointer', ['_IN_ADDR']]]],
    } ],
    '_TCP_LISTENER': [ None, { # TcpL
        'AddressFamily' : [ 0xC, ['unsigned char']],
        'Owner' : [ 0x18, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [ 0x20, ['WinTimeStamp', {}]],
        'LocalAddr' : [ 0x34, ['pointer', ['_LOCAL_ADDRESS']]],
        'InetAF' : [ 0x38, ['pointer', ['_INETAF']]],
        'Port' : [ 0x3E, ['unsigned short']],
    } ],
    '_TCP_ENDPOINT': [ None, { # TcpE
        'InetAF' : [ 0xC, ['pointer', ['_INETAF']]],
        'AddrInfo' : [ 0x10, ['pointer', ['_ADDRINFO']]],
        'ListEntry' : [ 0x14, ['_LIST_ENTRY']],
        'State' : [ 0x28, ['unsigned int']],
        'LocalPort' : [ 0x2C, ['unsigned short']],
        'RemotePort' : [ 0x2E, ['unsigned short']],
        'Owner' : [ 0x160, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [ 0x168, ['WinTimeStamp', {}]],
    } ],
    '_INETAF' : [ None, {
        'AddressFamily' : [ 0xC, ['unsigned short']],
    } ],
    '_ADDRINFO' : [ None, {
        'Local' : [ 0x0, ['pointer', ['_LOCAL_ADDRESS']]],
        'Remote' : [ 0x8, ['pointer', ['_IN_ADDR']]],
    } ],
    '_UDP_ENDPOINT': [ None, { # UdpA
        'Owner' : [ 0x18, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [ 0x30, ['WinTimeStamp', {}]],
        'LocalAddr' : [ 0x38, ['pointer', ['_LOCAL_ADDRESS']]],
        'InetAF' : [ 0x14, ['pointer', ['_INETAF']]],
        'AddressFamily' : [ 0x40, ['unsigned char']],
        'Port' : [ 0x48, ['unsigned short']],
    } ],
}

tcpip_vtypes_7 = {
    '_TCP_ENDPOINT': [ None, { # TcpE
        'InetAF' : [ 0xC, ['pointer', ['_INETAF']]],
        'AddrInfo' : [ 0x10, ['pointer', ['_ADDRINFO']]],
        'ListEntry' : [ 0x14, ['_LIST_ENTRY']],
        'State' : [ 0x34, ['unsigned int']],
        'LocalPort' : [ 0x38, ['unsigned short']],
        'RemotePort' : [ 0x3A, ['unsigned short']],
        'Owner' : [ 0x174, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [ 0x180, ['WinTimeStamp', {}]],
    } ],
}
