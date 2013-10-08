# fileobjscan.py
# Copyright 2009 Andreas Schuster <a.schuster@yendor.net>
# Copyright (C) 2009-2013 Volatility Foundation
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
@author:       Andreas Schuster
@license:      GNU General Public License 2.0
@contact:      a.schuster@forensikblog.de
@organization: http://computer.forensikblog.de/en/
"""

import volatility.scan as scan
import volatility.plugins.common as common
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.utils as utils
import volatility.obj as obj

class PoolScanFile(scan.PoolScanner):
    """PoolScanner for File objects"""
    checks = [ ('PoolTagCheck', dict(tag = "Fil\xe5")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x98)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class FileScan(common.AbstractWindowsCommand):
    """ Scan Physical memory for _FILE_OBJECT pool allocations
    """
    # Declare meta information associated with this plugin
    meta_info = {}
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.1'

    # Can't be cached until self.kernel_address_space is moved entirely within calculate
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')

        ## Will need the kernel AS for later:
        kernel_as = utils.load_as(self._config)

        for offset in PoolScanFile().scan(address_space):

            pool_obj = obj.Object("_POOL_HEADER", vm = address_space,
                                 offset = offset)

            ## We work out the _FILE_OBJECT from the end of the
            ## allocation (bottom up).
            pool_alignment = obj.VolMagic(address_space).PoolAlignment.v()

            file_obj = obj.Object("_FILE_OBJECT", vm = address_space,
                     offset = (offset + pool_obj.BlockSize * pool_alignment -
                     common.pool_align(kernel_as, "_FILE_OBJECT", pool_alignment)),
                     native_vm = kernel_as
                     )

            ## The _OBJECT_HEADER is immediately below the _FILE_OBJECT
            object_obj = obj.Object("_OBJECT_HEADER", vm = address_space,
                                   offset = file_obj.obj_offset -
                                   address_space.profile.get_obj_offset('_OBJECT_HEADER', 'Body'),
                                   native_vm = kernel_as
                                   )

            if object_obj.get_object_type() != "File":
                continue

            ## If the string is not reachable we skip it
            if not file_obj.FileName.v():
                continue

            yield (object_obj, file_obj)

    def render_text(self, outfd, data):

        self.table_header(outfd, [('Offset(P)', '[addrpad]'),
                                  ('#Ptr', '>6'),
                                  ('#Hnd', '>6'),
                                  ('Access', '>6'),
                                  ('Name', '')
                                  ])

        for object_obj, file_obj in data:
            self.table_row(outfd,
                         file_obj.obj_offset, object_obj.PointerCount,
                         object_obj.HandleCount, file_obj.access_string(), str(file_obj.file_name_with_device() or ''))

class PoolScanDriver(PoolScanFile):
    """ Scanner for _DRIVER_OBJECT """
    checks = [ ('PoolTagCheck', dict(tag = "Dri\xf6")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0xf8)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class DriverScan(FileScan):
    "Scan for driver objects _DRIVER_OBJECT "
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')

        ## Will need the kernel AS for later:
        kernel_as = utils.load_as(self._config)

        for offset in PoolScanDriver().scan(address_space):
            pool_obj = obj.Object("_POOL_HEADER", vm = address_space,
                                 offset = offset)

            ## We work out the _DRIVER_OBJECT from the end of the
            ## allocation (bottom up).
            pool_alignment = obj.VolMagic(address_space).PoolAlignment.v()

            extension_obj = obj.Object(
                "_DRIVER_EXTENSION", vm = address_space,
                offset = (offset + pool_obj.BlockSize * pool_alignment -
                          common.pool_align(kernel_as, "_DRIVER_EXTENSION", pool_alignment)),
                native_vm = kernel_as)

            ## The _DRIVER_OBJECT is immediately below the _DRIVER_EXTENSION
            driver_obj = obj.Object(
                "_DRIVER_OBJECT", vm = address_space,
                offset = extension_obj.obj_offset -
                    common.pool_align(kernel_as, "_DRIVER_OBJECT", pool_alignment),
                native_vm = kernel_as
                )

            ## The _OBJECT_HEADER is immediately below the _DRIVER_OBJECT
            object_obj = obj.Object(
                "_OBJECT_HEADER", vm = address_space,
                offset = driver_obj.obj_offset -
                address_space.profile.get_obj_offset('_OBJECT_HEADER', 'Body'),
                native_vm = kernel_as
                )

            ## Skip unallocated objects
            #if object_obj.Type == 0xbad0b0b0:
            #    continue

            if object_obj.get_object_type() != "Driver":
                continue

            yield (object_obj, driver_obj, extension_obj)


    def render_text(self, outfd, data):
        """Renders the text-based output"""
        self.table_header(outfd, [('Offset(P)', '[addrpad]'),
                                  ('#Ptr', '>4'),
                                  ('#Hnd', '>4'),
                                  ('Start', '[addrpad]'),
                                  ('Size', '[addr]'),
                                  ('Service Key', '20'),
                                  ('Name', '12'),
                                  ('Driver Name', '')
                                  ])

        for object_obj, driver_obj, extension_obj in data:

            self.table_row(outfd,
                         driver_obj.obj_offset, object_obj.PointerCount,
                         object_obj.HandleCount,
                         driver_obj.DriverStart, driver_obj.DriverSize,
                         str(extension_obj.ServiceKeyName or ''),
                         str(object_obj.NameInfo.Name or ''),
                         str(driver_obj.DriverName or ''))

class PoolScanSymlink(PoolScanFile):
    """ Scanner for symbolic link objects """
    checks = [ ('PoolTagCheck', dict(tag = "Sym\xe2")),
               # We use 0x48 as the lower bounds instead of 0x50 as described by Andreas
               # http://computer.forensikblog.de/en/2009/04/symbolic_link_objects.html. 
               # This is because the _OBJECT_SYMBOLIC_LINK structure size is 2 bytes smaller
               # on Windows 7 (a field was removed) than on all other OS versions. 
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x48)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ]

class SymLinkScan(FileScan):
    "Scan for symbolic link objects "
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')

        ## Will need the kernel AS for later:
        kernel_as = utils.load_as(self._config)

        for offset in PoolScanSymlink().scan(address_space):
            pool_obj = obj.Object("_POOL_HEADER", vm = address_space,
                                 offset = offset)

            ## We work out the object from the end of the
            ## allocation (bottom up).
            pool_alignment = obj.VolMagic(address_space).PoolAlignment.v()

            link_obj = obj.Object("_OBJECT_SYMBOLIC_LINK", vm = address_space,
                     offset = (offset + pool_obj.BlockSize * pool_alignment -
                               common.pool_align(kernel_as, "_OBJECT_SYMBOLIC_LINK", pool_alignment)),
                     native_vm = kernel_as)

            ## The _OBJECT_HEADER is immediately below the _OBJECT_SYMBOLIC_LINK
            object_obj = obj.Object(
                "_OBJECT_HEADER", vm = address_space,
                offset = link_obj.obj_offset -
                address_space.profile.get_obj_offset('_OBJECT_HEADER', 'Body'),
                native_vm = kernel_as
                )

            if object_obj.get_object_type() != "SymbolicLink":
                continue

            yield object_obj, link_obj

    def render_text(self, outfd, data):
        """ Renders text-based output """

        self.table_header(outfd, [('Offset(P)', '[addrpad]'),
                                  ('#Ptr', '>6'),
                                  ('#Hnd', '>6'),
                                  ('Creation time', '30'),
                                  ('From', '<20'),
                                  ('To', '60'),
                                  ])

        for objct, link in data:
            self.table_row(outfd,
                        link.obj_offset, objct.PointerCount,
                        objct.HandleCount, link.CreationTime or '',
                        str(objct.NameInfo.Name or ''),
                        str(link.LinkTarget or ''))

class PoolScanMutant(PoolScanDriver):
    """ Scanner for Mutants _KMUTANT """
    checks = [ ('PoolTagCheck', dict(tag = "Mut\xe1")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x40)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]


class MutantScan(FileScan):
    "Scan for mutant objects _KMUTANT "
    def __init__(self, config, *args, **kwargs):
        FileScan.__init__(self, config, *args, **kwargs)
        config.add_option("SILENT", short_option = 's', default = False,
                          action = 'store_true', help = 'Suppress less meaningful results')

    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')

        ## Will need the kernel AS for later:
        kernel_as = utils.load_as(self._config)

        for offset in PoolScanMutant().scan(address_space):
            pool_obj = obj.Object("_POOL_HEADER", vm = address_space,
                                 offset = offset)

            ## We work out the _DRIVER_OBJECT from the end of the
            ## allocation (bottom up).
            pool_alignment = obj.VolMagic(address_space).PoolAlignment.v()

            mutant = obj.Object(
                "_KMUTANT", vm = address_space,
                offset = (offset + pool_obj.BlockSize * pool_alignment -
                          common.pool_align(kernel_as, "_KMUTANT", pool_alignment)),
                native_vm = kernel_as)

            ## The _OBJECT_HEADER is immediately below the _KMUTANT
            object_obj = obj.Object(
                "_OBJECT_HEADER", vm = address_space,
                offset = mutant.obj_offset -
                address_space.profile.get_obj_offset('_OBJECT_HEADER', 'Body'),
                native_vm = kernel_as
                )

            if object_obj.get_object_type() != "Mutant":
                continue

            ## Skip unallocated objects
            ##if object_obj.Type == 0xbad0b0b0:
            ##   continue

            if self._config.SILENT:
                if len(object_obj.NameInfo.Name) == 0:
                    continue

            yield (object_obj, mutant)


    def render_text(self, outfd, data):
        """Renders the output"""

        self.table_header(outfd, [('Offset(P)', '[addrpad]'),
                                  ('#Ptr', '>4'),
                                  ('#Hnd', '>4'),
                                  ('Signal', '4'),
                                  ('Thread', '[addrpad]'),
                                  ('CID', '>9'),
                                  ('Name', '')
                                  ])

        for object_obj, mutant in data:
            if mutant.OwnerThread > 0x80000000:
                thread = mutant.OwnerThread.dereference_as('_ETHREAD')
                CID = "{0}:{1}".format(thread.Cid.UniqueProcess, thread.Cid.UniqueThread)
            else:
                CID = ""

            self.table_row(outfd,
                         mutant.obj_offset, object_obj.PointerCount,
                         object_obj.HandleCount, mutant.Header.SignalState,
                         mutant.OwnerThread, CID,
                         str(object_obj.NameInfo.Name or '')
                         )

class CheckProcess(scan.ScannerCheck):
    """ Check sanity of _EPROCESS """
    kernel = 0x80000000

    def check(self, found):
        ## The offset of the object is determined by subtracting the offset
        ## of the PoolTag member to get the start of Pool Object. This done
        ## because PoolScanners search for the PoolTag. 
        pool_base = found - self.address_space.profile.get_obj_offset(
            '_POOL_HEADER', 'PoolTag')

        pool_obj = obj.Object("_POOL_HEADER", vm = self.address_space,
                                 offset = pool_base)

        ## We work out the _EPROCESS from the end of the
        ## allocation (bottom up).
        pool_alignment = obj.VolMagic(self.address_space).PoolAlignment.v()
        eprocess = obj.Object("_EPROCESS", vm = self.address_space,
                  offset = pool_base + pool_obj.BlockSize * pool_alignment -
                  common.pool_align(self.address_space, '_EPROCESS', pool_alignment))

        if (eprocess.Pcb.DirectoryTableBase == 0):
            return False

        if (eprocess.Pcb.DirectoryTableBase % 0x20 != 0):
            return False

        list_head = eprocess.ThreadListHead

        if (list_head.Flink < self.kernel) or (list_head.Blink < self.kernel):
            return False

        return True


class PoolScanProcess(scan.PoolScanner):
    """PoolScanner for File objects"""

    def object_offset(self, found, address_space):
        """ This returns the offset of the object contained within
        this pool allocation.
        """
        ## The offset of the object is determined by subtracting the offset
        ## of the PoolTag member to get the start of Pool Object and then
        ## walking backwards based on pool alignment and pool size. 

        pool_base = found - self.buffer.profile.get_obj_offset(
            '_POOL_HEADER', 'PoolTag')

        pool_obj = obj.Object("_POOL_HEADER", vm = address_space,
                                 offset = pool_base)

        ## We work out the _EPROCESS from the end of the
        ## allocation (bottom up).
        pool_alignment = obj.VolMagic(address_space).PoolAlignment.v()

        object_base = (pool_base + pool_obj.BlockSize * pool_alignment -
                       common.pool_align(address_space, '_EPROCESS', pool_alignment))

        return object_base

    checks = [ ('PoolTagCheck', dict(tag = '\x50\x72\x6F\xe3')),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x1ae)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ('CheckProcess', {}),
               ]


class PSScan(common.AbstractWindowsCommand):
    """ Scan Physical memory for _EPROCESS pool allocations
    """
    # Declare meta information associated with this plugin
    meta_info = {}
    meta_info['author'] = 'AAron Walters'
    meta_info['copyright'] = 'Copyright (c) 2011 Volatility Foundation'
    meta_info['contact'] = 'awalters@4tphi.net'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'https://www.volatilityfoundation.org/'
    meta_info['os'] = ['Win7SP0x86', 'WinXPSP3x86']
    meta_info['version'] = '0.1'

    # Can't be cached until self.kernel_address_space is moved entirely
    # within calculate
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')
        kernel_as = utils.load_as(self._config)

        for offset in PoolScanProcess().scan(address_space):
            eprocess = obj.Object('_EPROCESS', vm = address_space,
                                  native_vm = kernel_as, offset = offset)
            yield eprocess


    def render_text(self, outfd, data):

        self.table_header(outfd, [('Offset(P)', '[addrpad]'),
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

