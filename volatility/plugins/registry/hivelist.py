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
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def render_text(self, outfd, result):
        outfd.write("{0:10}  {1:10}  {2}\n".format("Virtual", "Physical", "Name"))

        hive_offsets = []

        for hive in result:
            if hive.obj_offset not in hive_offsets:
                try:
                    name = hive.FileFullPath.v() or hive.FileUserName.v() or hive.HiveRootPath.v() or "[no name]"
                except AttributeError:
                    name = "[no name]"
                # Spec of 10 rather than 8 width, since the # puts 0x at the start, which is included in the width
                outfd.write("{0:#010x}  {1:#010x}  {2}\n".format(hive.obj_offset, hive.obj_vm.vtop(hive.obj_offset), name))
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
