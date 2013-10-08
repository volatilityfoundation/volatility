# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

"""
This module implements the fast socket scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
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
        license = 'GNU General Public License 2.0',
        url = 'http://moyix.blogspot.com/',
        os = 'WIN_32_XP_SP2',
        version = '1.0',
        )

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 5)

    @cache.CacheDecorator("tests/sockscan")
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')
        if not self.is_valid_profile(address_space.profile):
            debug.error("This command does not support the selected profile.")
        scanner = PoolScanSockFast()
        for offset in scanner.scan(address_space):
            yield obj.Object('_ADDRESS_OBJECT', vm = address_space, offset = offset)

    def render_text(self, outfd, data):

        self.table_header(outfd, [('Offset(P)', '[addrpad]'),
                                  ('PID', '>8'),
                                  ('Port', '>6'),
                                  ('Proto', '>6'),
                                  ('Protocol', '15'),
                                  ('Address', '15'),
                                  ('Create Time', '')
                                  ])

        for sock_obj in data:
            self.table_row(outfd,
                           sock_obj.obj_offset,
                           sock_obj.Pid,
                           sock_obj.LocalPort,
                           sock_obj.Protocol,
                           protos.protos.get(sock_obj.Protocol.v(), "-"),
                           sock_obj.LocalIpAddress,
                           sock_obj.CreateTime)
