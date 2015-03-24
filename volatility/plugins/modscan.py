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
This module implements the fast module scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

import common
from volatility import renderers
import volatility.plugins.filescan as filescan
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.poolscan as poolscan
from volatility.renderers.basic import Address, Hex


class PoolScanModule(poolscan.PoolScanner):
    """Pool scanner for kernel modules"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.struct_name = "_LDR_DATA_TABLE_ENTRY"
        self.pooltag = "MmLd"
        self.checks = [
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x4C)),
               ('CheckPoolType', dict(paged = False, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class ModScan(common.AbstractScanCommand):
    """Pool scanner for kernel modules"""

    scanners = [PoolScanModule]

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

    def unified_output(self, data):
        def generator(data):
            for ldr_entry in data:
                yield (0,
                             [Address(ldr_entry.obj_offset),
                             str(ldr_entry.BaseDllName or ''),
                             Address(ldr_entry.DllBase),
                             Hex(ldr_entry.SizeOfImage),
                             str(ldr_entry.FullDllName or '')])

        return renderers.TreeGrid(
            [(self.offset_column(), Address),
             ('Name', str),
             ('Base', Address),
             ('Size', Hex),
             ('File', str)
            ], generator(data))

    def render_text(self, outfd, data):
        self.table_header(outfd,
                          [(self.offset_column(), "#018x"),
                           ('Name', "20"),
                           ('Base', "[addrpad]"),
                           ('Size', "[addr]"),
                           ('File', "")
                           ])
        for ldr_entry in data:
            self.table_row(outfd,
                         ldr_entry.obj_offset,
                         str(ldr_entry.BaseDllName or ''),
                         ldr_entry.DllBase,
                         ldr_entry.SizeOfImage,
                         str(ldr_entry.FullDllName or ''))

class PoolScanThread(poolscan.PoolScanner):
    """Pool scanner for thread objects"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.struct_name = "_ETHREAD"
        self.object_type = "Thread"
        # this allows us to find terminated threads
        self.skip_type_check = True
        self.pooltag = obj.VolMagic(address_space).ThreadPoolTag.v()
        size = 0x278 # self.address_space.profile.get_obj_size("_ETHREAD")

        self.checks = [
               ('CheckPoolSize', dict(condition = lambda x: x >= size)),
               ('CheckPoolType', dict(paged = False, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class ThrdScan(common.AbstractScanCommand):
    """Pool scanner for thread objects"""

    scanners = [PoolScanThread]

    def unified_output(self, data):
        def generator(data):
            for thread in data:
                yield (0, [Address(thread.obj_offset),
                               int(thread.Cid.UniqueProcess),
                               int(thread.Cid.UniqueThread),
                               Address(thread.StartAddress),
                               str(thread.CreateTime or ''),
                               str(thread.ExitTime or '')]
                               )
        return renderers.TreeGrid(
            [(self.offset_column(), Address),
             ("PID", int),
             ("TID", int),
             ("Start Address", Address),
             ("Create Time", str),
             ("Exit Time", str),
            ], generator(data))

    def render_text(self, outfd, data):
        self.table_header(outfd,
                          [(self.offset_column(), "#018x"),
                           ("PID", ">6"),
                           ("TID", ">6"),
                           ("Start Address", "[addr]"),
                           ("Create Time", "30"),
                           ("Exit Time", "30"),
                           ])

        for thread in data:
            self.table_row(outfd, thread.obj_offset,
                           thread.Cid.UniqueProcess,
                           thread.Cid.UniqueThread,
                           thread.StartAddress,
                           thread.CreateTime or '',
                           thread.ExitTime or '',
                           )

