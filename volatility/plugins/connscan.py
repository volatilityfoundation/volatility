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
This module implements the fast connection scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import volatility.scan as scan
import volatility.commands as commands
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

class ConnScan(commands.command):
    """ Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
    """
    meta_info = dict(
        author = 'Brendan Dolan-Gavitt',
        copyright = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        contact = 'bdolangavitt@wesleyan.edu',
        license = 'GNU General Public License 2.0 or later',
        url = 'http://moyix.blogspot.com/',
        os = 'WIN_32_XP_SP2',
        version = '1.0',
        )

    @cache.CacheDecorator("scans/connscan2")
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = PoolScanConnFast()
        for offset in scanner.scan(address_space):
            ## This yields the pool offsets - we want the actual object
            tcp_obj = obj.Object('_TCPT_OBJECT', vm = address_space,
                                offset = offset)
            yield tcp_obj

    def render_text(self, outfd, data):
        outfd.write(" Offset(P)  Local Address             Remote Address            Pid   \n" + \
                    "---------- ------------------------- ------------------------- ------ \n")

        for tcp_obj in data:
            local = "{0}:{1}".format(tcp_obj.LocalIpAddress, tcp_obj.LocalPort)
            remote = "{0}:{1}".format(tcp_obj.RemoteIpAddress, tcp_obj.RemotePort)
            outfd.write("{0:#010x} {1:25} {2:25} {3:6}\n".format(tcp_obj.obj_offset, local, remote, tcp_obj.Pid))
