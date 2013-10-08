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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

import volatility.plugins.registry.hivescan as hs
import volatility.obj as obj
import volatility.utils as utils
import volatility.cache as cache

class HiveList(hs.HiveScan):
    """Print list of registry hives.

    You can supply the offset of a specific hive. Otherwise
    this module will use the results from hivescan automatically.
    """
    # Declare meta information associated with this plugin

    meta_info = {}
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def render_text(self, outfd, result):

        self.table_header(outfd, [('Virtual', '[addrpad]'),
                                  ('Physical', '[addrpad]'),
                                  ('Name', ''),
                                  ])

        hive_offsets = []

        for hive in result:
            if hive.Hive.Signature == 0xbee0bee0 and hive.obj_offset not in hive_offsets:
                try:
                    name = str(hive.FileFullPath or '') or str(hive.FileUserName or '') or str(hive.HiveRootPath or '') or "[no name]"
                except AttributeError:
                    name = "[no name]"
                # Spec of 10 rather than 8 width, since the # puts 0x at the start, which is included in the width
                self.table_row(outfd, hive.obj_offset, hive.obj_vm.vtop(hive.obj_offset), name)
                hive_offsets.append(hive.obj_offset)

    @cache.CacheDecorator("tests/hivelist")
    def calculate(self):
        flat = utils.load_as(self._config, astype = 'physical')
        addr_space = utils.load_as(self._config)

        hives = hs.HiveScan.calculate(self)

        ## The first hive is normally given in physical address space
        ## - so we instantiate it using the flat address space. We
        ## then read the Flink of the list to locate the address of
        ## the first hive in virtual address space. hmm I wish we
        ## could go from physical to virtual memory easier.
        for offset in hives:
            hive = obj.Object("_CMHIVE", int(offset), flat, native_vm = addr_space)
            if hive.HiveList.Flink.v():
                start_hive_offset = hive.HiveList.Flink.v() - addr_space.profile.get_obj_offset('_CMHIVE', 'HiveList')

                ## Now instantiate the first hive in virtual address space as normal
                start_hive = obj.Object("_CMHIVE", start_hive_offset, addr_space)

                for hive in start_hive.HiveList:
                    yield hive
