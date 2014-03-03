# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

"""
This module implements the fast socket scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

import volatility.poolscan as poolscan
import volatility.plugins.common as common
import volatility.protos as protos

class PoolScanSocket(poolscan.PoolScanner):
    """Pool scanner for tcp socket objects"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.struct_name = "_ADDRESS_OBJECT"
        self.pooltag = "TCPA"

        self.checks = [('CheckPoolSize', dict(condition = lambda x: x >= 0x15C)),
                   ('CheckPoolType', dict(non_paged = True, free = True)),
                   ## Valid sockets have time > 0
                   #('CheckSocketCreateTime', dict(condition = lambda x: x > 0)),
                   ('CheckPoolIndex', dict(value = 0))
                   ]

class SockScan(common.AbstractScanCommand):
    """Pool scanner for tcp socket objects"""

    scanners = [PoolScanSocket]
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

    def render_text(self, outfd, data):

        self.table_header(outfd, [(self.offset_column(), '[addrpad]'),
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
