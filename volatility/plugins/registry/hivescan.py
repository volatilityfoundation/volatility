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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import volatility.scan as scan
import volatility.obj as obj
import volatility.utils as utils
import volatility.commands as commands
import volatility.cache as cache

class CheckHiveSig(scan.ScannerCheck):
    """ Check for a registry hive signature """
    def check(self, offset):

        # Instead of hard-coding 4 here, calculate it safely in case 
        # additional fields are added to _POOL_HEADER after the pool tag. 
        offset += (self.address_space.profile.get_obj_size("_POOL_HEADER") -
                   self.address_space.profile.get_obj_offset("_POOL_HEADER", "PoolTag"))

        # We don't need to use pool alignment here because we're not 
        # carving from the bottom-up like other objects. There is no
        # object header or optional headers for _HHIVE. 

        sig = obj.Object('_HHIVE', vm = self.address_space, offset = offset).Signature
        return sig == 0xbee0bee0

class PoolScanHiveFast2(scan.PoolScanner):

    def object_offset(self, found, address_space):
        return found + (address_space.profile.get_obj_size("_POOL_HEADER") -
                        address_space.profile.get_obj_offset("_POOL_HEADER", "PoolTag"))

    checks = [ ('PoolTagCheck', dict(tag = "CM10")),
               # Dummy condition, since this will be changed during initialization
               ('CheckPoolSize', dict(condition = lambda x: x == 0x638)),
               #('CheckPoolType', dict(non_paged = True)), #doesn't work for win7 and vista
               ('CheckHiveSig', {})
               ]

    def __init__(self, poolsize):
        self.checks[1] = ('CheckPoolSize', dict(condition = lambda x: x >= poolsize))
        scan.PoolScanner.__init__(self)

class HiveScan(commands.Command):
    """ Scan Physical memory for _CMHIVE objects (registry hives)

    You will need to obtain these offsets to feed into the hivelist command.
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

    @cache.CacheDecorator("tests/hivescan")
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        pspace = utils.load_as(self._config, astype = 'physical')
        poolsize = pspace.profile.get_obj_size('_CMHIVE')

        return PoolScanHiveFast2(poolsize).scan(pspace)

    def render_text(self, outfd, data):
        outfd.write("{0:15} {1:15}\n".format("Offset(P)", "(hex)"))
        for offset in data:
            outfd.write("{0:<15} {1:#010x}\n".format(offset, offset))
