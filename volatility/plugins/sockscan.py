# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

"""
This module implements the fast socket scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import volatility.scan as scan
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.cache as cache
import volatility.protos as protos

class CheckSocketCreateTime(scan.ScannerCheck):
    """ Check that _ADDRESS_OBJECT.CreateTime makes sense """
    def __init__(self, address_space, condition = lambda x: x, *args, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, *args, **kwargs)
        self.condition = condition

    def check(self, offset):
        """ The offset parameter here is the start of PoolTag as yielded   
        by BaseScanner.scan. Unlike other objects, _ADDRESS_OBJECT do not
        have an _OBJECT_HEADER or any optional headers. Thus to find the 
        _ADDRESS_OBJECT from the PoolTag we just have to calculate the 
        distance from PoolTag to the end of _POOL_HEADER.
        """
        start_of_object = (self.address_space.profile.get_obj_size("_POOL_HEADER") -
                          self.address_space.profile.get_obj_offset("_POOL_HEADER", "PoolTag"))
        address_obj = obj.Object('_ADDRESS_OBJECT', vm = self.address_space,
                                offset = offset + start_of_object)

        return self.condition(address_obj.CreateTime.v())

class PoolScanSockFast(scan.PoolScanner):

    def object_offset(self, found, address_space):
        """ Return the offset of _ADDRESS_OBJECT """
        return found + (address_space.profile.get_obj_size("_POOL_HEADER") -
                        address_space.profile.get_obj_offset("_POOL_HEADER", "PoolTag"))

    checks = [ ('PoolTagCheck', dict(tag = "TCPA")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x15C)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ## Valid sockets have time > 0
               ('CheckSocketCreateTime', dict(condition = lambda x: x > 0)),
               ('CheckPoolIndex', dict(value = 0))
               ]

class SockScan(common.AbstractWindowsCommand):
    """ Scan Physical memory for _ADDRESS_OBJECT objects (tcp sockets)
    """

    # Declare meta information associated with this plugin

    meta_info = dict(
        author = 'Brendan Dolan-Gavitt',
        copyright = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        contact = 'bdolangavitt@wesleyan.edu',
        license = 'GNU General Public License 2.0 or later',
        url = 'http://moyix.blogspot.com/',
        os = 'WIN_32_XP_SP2',
        version = '1.0',
        )

    @cache.CacheDecorator("tests/sockscan")
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')
        scanner = PoolScanSockFast()
        for offset in scanner.scan(address_space):
            yield obj.Object('_ADDRESS_OBJECT', vm = address_space, offset = offset)

    def render_text(self, outfd, data):

        outfd.write(" Offset(P)  PID    Port   Proto               Address        Create Time               \n" +
                    "---------- ------ ------ ------------------- -------------- -------------------------- \n")

        for sock_obj in data:
            outfd.write("{0:#010x} {1:6} {2:6} {3:6} {4:14} {5:18} {6:26}\n".format(sock_obj.obj_offset, sock_obj.Pid,
                                                                      sock_obj.LocalPort,
                                                                      sock_obj.Protocol,
                                                                      protos.protos.get(sock_obj.Protocol.v(), "-"),
                                                                      sock_obj.LocalIpAddress,
                                                                      sock_obj.CreateTime))
