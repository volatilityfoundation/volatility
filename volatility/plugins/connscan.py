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
This module implements the fast connection scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

import volatility.scan as scan
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611

class PoolScanConnFast(scan.PoolScanner):

    def object_offset(self, found, address_space):
        """ Return the offset of _TCPT_OBJECT """
        return found + (address_space.profile.get_obj_size("_POOL_HEADER") -
                        address_space.profile.get_obj_offset("_POOL_HEADER", "PoolTag"))

    checks = [ ('PoolTagCheck', dict(tag = "TCPT")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x198)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class ConnScan(common.AbstractWindowsCommand):
    """ Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
    """
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

    @cache.CacheDecorator("scans/connscan2")
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')

        if not self.is_valid_profile(address_space.profile):
            debug.error("This command does not support the selected profile.")

        scanner = PoolScanConnFast()
        for offset in scanner.scan(address_space):
            ## This yields the pool offsets - we want the actual object
            tcp_obj = obj.Object('_TCPT_OBJECT', vm = address_space,
                                offset = offset)
            yield tcp_obj

    def render_text(self, outfd, data):
        self.table_header(outfd,
                          [("Offset(P)", "[addrpad]"),
                           ("Local Address", "25"),
                           ("Remote Address", "25"),
                           ("Pid", "")
                           ])

        for tcp_obj in data:
            local = "{0}:{1}".format(tcp_obj.LocalIpAddress, tcp_obj.LocalPort)
            remote = "{0}:{1}".format(tcp_obj.RemoteIpAddress, tcp_obj.RemotePort)
            self.table_row(outfd,
                            tcp_obj.obj_offset,
                            local, remote,
                            tcp_obj.Pid)
