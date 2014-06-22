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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

import volatility.utils as utils 
import volatility.poolscan as poolscan
import volatility.plugins.common as common
import volatility.plugins.bigpagepools as bigpools

class PoolScanHive(poolscan.PoolScanner):
    """Pool scanner for registry hives"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)
        self.struct_name = "_CMHIVE"
        self.pooltag = "CM10"
        size = self.address_space.profile.get_obj_size("_CMHIVE")
        self.checks = [ 
                   ('CheckPoolSize', dict(condition = lambda x: x >= size)),
                   ]

class HiveScan(common.AbstractScanCommand):
    """Pool scanner for registry hives"""

    scanners = [PoolScanHive]
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

    def calculate(self):
        addr_space = utils.load_as(self._config)

        metadata = addr_space.profile.metadata
        version = (metadata.get("major", 0), metadata.get("minor", 0))
        arch = metadata.get("memory_model", "32bit")

        if version >= (6, 3) and arch == "64bit":
            for pool in bigpools.BigPagePoolScanner(addr_space).scan(["CM10"]):
                yield pool.Va.dereference_as("_CMHIVE")
        else:
            for result in self.scan_results(addr_space):
                yield result

    def render_text(self, outfd, data):
        self.table_header(outfd, [('Offset(P)', '[addrpad]')])
        for hive in data:
            self.table_row(outfd, hive.obj_offset)
