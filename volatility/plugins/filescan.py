# fileobjscan.py
# Copyright 2009 Andreas Schuster <a.schuster@yendor.net>
# Copyright (C) 2009-2013 Volatility Foundation
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
@author:       Andreas Schuster
@license:      GNU General Public License 2.0
@contact:      a.schuster@forensikblog.de
@organization: http://computer.forensikblog.de/en/
"""

import volatility.plugins.common as common
import volatility.obj as obj
import volatility.poolscan as poolscan
import volatility.utils as utils

class PoolScanFile(poolscan.PoolScanner):
    """Pool scanner for file objects"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.struct_name = "_FILE_OBJECT"
        self.object_type = "File"
        self.pooltag = obj.VolMagic(address_space).FilePoolTag.v()
        size = 0x98 # self.address_space.profile.get_obj_size("_FILE_OBJECT")

        self.checks = [ 
               ('CheckPoolSize', dict(condition = lambda x: x >= size)),
               ('CheckPoolType', dict(paged = False, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class FileScan(common.AbstractScanCommand):
    """Pool scanner for file objects"""

    scanners = [PoolScanFile]

    # Declare meta information associated with this plugin
    meta_info = {}
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.1'

    def render_text(self, outfd, data):

        self.table_header(outfd, [(self.offset_column(), '#018x'),
                                  ('#Ptr', '>6'),
                                  ('#Hnd', '>6'),
                                  ('Access', '>6'),
                                  ('Name', '')
                                  ])

        for file in data:
            header = file.get_object_header()
            self.table_row(outfd,
                         file.obj_offset, 
                         header.PointerCount,
                         header.HandleCount, 
                         file.access_string(), 
                         str(file.file_name_with_device() or ''))

class PoolScanDriver(poolscan.PoolScanner):
    """Pool scanner for driver objects"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.struct_name = "_DRIVER_OBJECT"
        self.object_type = "Driver"
        # due to the placement of the driver extension, we 
        # use the top down approach instead of bottom-up.
        self.use_top_down = True
        self.pooltag = obj.VolMagic(address_space).DriverPoolTag.v()
        size = 0xf8 # self.address_space.profile.get_obj_size("_DRIVER_OBJECT")

        self.checks = [ 
               ('CheckPoolSize', dict(condition = lambda x: x >= size)),
               ('CheckPoolType', dict(paged = False, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class DriverScan(common.AbstractScanCommand):
    """Pool scanner for driver objects"""

    scanners = [PoolScanDriver]

    def render_text(self, outfd, data):
       
        self.table_header(outfd, [(self.offset_column(), '#018x'),
                                  ('#Ptr', '>8'),
                                  ('#Hnd', '>8'),
                                  ('Start', '[addrpad]'),
                                  ('Size', '[addr]'),
                                  ('Service Key', '20'),
                                  ('Name', '12'),
                                  ('Driver Name', '')
                                  ])

        for driver in data:
            header = driver.get_object_header()
            self.table_row(outfd,
                         driver.obj_offset, 
                         header.PointerCount,
                         header.HandleCount,
                         driver.DriverStart, 
                         driver.DriverSize,
                         str(driver.DriverExtension.ServiceKeyName or ''),
                         str(header.NameInfo.Name or ''),
                         str(driver.DriverName or ''))

class PoolScanSymlink(poolscan.PoolScanner):
    """Pool scanner for symlink objects"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.struct_name = "_OBJECT_SYMBOLIC_LINK"
        self.object_type = "SymbolicLink"
        self.pooltag = obj.VolMagic(address_space).SymlinkPoolTag.v()
        size = 0x48 # self.address_space.profile.get_obj_size("_OBJECT_SYMBOLIC_LINK")

        self.checks = [ 
               ('CheckPoolSize', dict(condition = lambda x: x >= size)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ]

class SymLinkScan(common.AbstractScanCommand):
    """Pool scanner for symlink objects"""

    scanners = [PoolScanSymlink]

    def render_text(self, outfd, data):

        self.table_header(outfd, [(self.offset_column(), '#018x'),
                                  ('#Ptr', '>6'),
                                  ('#Hnd', '>6'),
                                  ('Creation time', '30'),
                                  ('From', '<20'),
                                  ('To', '60'),
                                  ])

        for link in data:
            header = link.get_object_header()
            self.table_row(outfd,
                        link.obj_offset, 
                        header.PointerCount,
                        header.HandleCount, 
                        link.CreationTime or '',
                        str(header.NameInfo.Name or ''),
                        str(link.LinkTarget or ''))

class PoolScanMutant(poolscan.PoolScanner):
    """Pool scanner for mutex objects"""
    
    def __init__(self, address_space, **kwargs):
        poolscan.PoolScanner.__init__(self, address_space, **kwargs)

        self.struct_name = "_KMUTANT"
        self.object_type = "Mutant"
        self.pooltag = obj.VolMagic(address_space).MutexPoolTag.v()
        size = 0x40 # self.address_space.profile.get_obj_size("_KMUTANT")

        self.checks = [ 
               ('CheckPoolSize', dict(condition = lambda x: x >= size)),
               ('CheckPoolType', dict(paged = False, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class MutantScan(common.AbstractScanCommand):
    """Pool scanner for mutex objects"""

    scanners = [PoolScanMutant]

    def __init__(self, config, *args, **kwargs):
        common.AbstractScanCommand.__init__(self, config, *args, **kwargs)
        config.add_option("SILENT", short_option = 's', default = False,
                          action = 'store_true', 
                          help = 'Suppress less meaningful results')

    def render_text(self, outfd, data):

        self.table_header(outfd, [(self.offset_column(), '#018x'),
                                  ('#Ptr', '>8'),
                                  ('#Hnd', '>8'),
                                  ('Signal', '4'),
                                  ('Thread', '[addrpad]'),
                                  ('CID', '>9'),
                                  ('Name', '')
                                  ])

        for mutant in data:

            header = mutant.get_object_header()

            if mutant.OwnerThread.is_valid():
                thread = mutant.OwnerThread.dereference_as('_ETHREAD')
                CID = "{0}:{1}".format(thread.Cid.UniqueProcess, thread.Cid.UniqueThread)
            else:
                CID = ""

            self.table_row(outfd,
                         mutant.obj_offset, 
                         header.PointerCount,
                         header.HandleCount, 
                         mutant.Header.SignalState,
                         mutant.OwnerThread, CID,
                         str(header.NameInfo.Name or ''))

class PoolScanProcess(poolscan.PoolScanner):
    """Pool scanner for process objects"""

    def __init__(self, address_space, **kwargs):
        poolscan.PoolScanner.__init__(self, address_space, **kwargs)

        self.struct_name = "_EPROCESS"
        self.object_type = "Process"
        # this allows us to find terminated processes 
        self.skip_type_check = True
        self.pooltag = obj.VolMagic(address_space).ProcessPoolTag.v()
        size = 0x1ae # self.address_space.profile.get_obj_size("_EPROCESS")

        self.checks = [ 
                ('CheckPoolSize', dict(condition = lambda x: x >= size)),
                ('CheckPoolType', dict(paged = False, non_paged = True, free = True)),
                ('CheckPoolIndex', dict(value = 0)),
                ]

class PSScan(common.AbstractScanCommand):
    """Pool scanner for process objects"""

    scanners = [PoolScanProcess]

    # Declare meta information associated with this plugin
    meta_info = {}
    meta_info['author'] = 'AAron Walters'
    meta_info['copyright'] = 'Copyright (c) 2011 Volatility Foundation'
    meta_info['contact'] = 'awalters@4tphi.net'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'https://www.volatilityfoundation.org/'
    meta_info['os'] = ['Win7SP0x86', 'WinXPSP3x86']
    meta_info['version'] = '0.1'

    def calculate(self):
        if self._config.VIRTUAL:
            addr_space = utils.load_as(self._config)
        else:
            addr_space = utils.load_as(self._config, astype = 'physical')
        return self.scan_results(addr_space)

    def render_text(self, outfd, data):

        self.table_header(outfd, [(self.offset_column(), '#018x'),
                                  ('Name', '16'),
                                  ('PID', '>6'),
                                  ('PPID', '>6'),
                                  ('PDB', '[addrpad]'),
                                  ('Time created', '30'),
                                  ('Time exited', '30')
                                  ])

        for eprocess in data:

            self.table_row(outfd,
                          eprocess.obj_offset,
                          eprocess.ImageFileName,
                          eprocess.UniqueProcessId,
                          eprocess.InheritedFromUniqueProcessId,
                          eprocess.Pcb.DirectoryTableBase,
                          eprocess.CreateTime or '',
                          eprocess.ExitTime or '')

    def render_dot(self, outfd, data):
        objects = set()
        links = set()

        for eprocess in data:
            label = "{0} | {1} |".format(eprocess.UniqueProcessId,
                                         eprocess.ImageFileName)
            if eprocess.ExitTime:
                label += "exited\\n{0}".format(eprocess.ExitTime)
                options = ' style = "filled" fillcolor = "lightgray" '
            else:
                label += "running"
                options = ''

            objects.add('pid{0} [label="{1}" shape="record" {2}];\n'.format(eprocess.UniqueProcessId,
                                                                            label, options))
            links.add("pid{0} -> pid{1} [];\n".format(eprocess.InheritedFromUniqueProcessId,
                                                      eprocess.UniqueProcessId))

        ## Now write the dot file
        outfd.write("digraph processtree { \ngraph [rankdir = \"TB\"];\n")
        for link in links:
            outfd.write(link)

        for item in objects:
            outfd.write(item)
        outfd.write("}")

