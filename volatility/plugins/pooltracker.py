# Volatility
# Copyright (C) Michael Ligh <michael.ligh@mnin.org>
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

import os
import volatility.plugins.common as common
import volatility.utils as utils 
import volatility.win32.tasks as tasks
import volatility.obj as obj
import volatility.debug as debug
import volatility.poolscan as poolscan
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

#--------------------------------------------------------------------------------
# Profile Modifications 
#--------------------------------------------------------------------------------

class PoolTrackTagOverlay(obj.ProfileModification):
    """Overlays for pool trackers"""

    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):
        profile.merge_overlay({
            '_POOL_TRACKER_TABLE': [ None, {
            'Key': [ None, ['String', dict(length = 4)]]
             }],
        })

#--------------------------------------------------------------------------------
# PoolTracker Plugin
#--------------------------------------------------------------------------------

class PoolTracker(common.AbstractWindowsCommand):
    """Show a summary of pool tag usage"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('TAGS', short_option = 't', help = 'Pool tag to find')
        config.add_option('TAGFILE', short_option = 'T', 
                help = 'Pool tag file (pooltag.txt)', default = None) 
        config.add_option('WHITELIST', short_option = 'W', 
                help = 'Apply whitelist (only show third party tags)', 
                default = False, action = "store_true")
        config.add_option('SHOW-FREE', short_option = 'F', 
                help = 'Show tags with no allocations', 
                default = False, action = "store_true")

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 6)

    def calculate(self):
        kernel_space = utils.load_as(self._config)

        if not self.is_valid_profile(kernel_space.profile):
            debug.error("Windows XP/2003 does not track pool tags")

        knowntags = {}
        if self._config.TAGFILE and os.path.isfile(self._config.TAGFILE):
            taglines = open(self._config.TAGFILE).readlines()
            for tag in taglines:
                tag = tag.strip()
                if tag.startswith("rem") or tag.startswith(" ") or tag == "":
                    continue
                info = tag.split("-", 2)
                try:
                    key = info[0].strip()
                    driver = info[1].strip()
                    reason = info[2].strip()
                except IndexError:
                    continue
                knowntags[key] = (driver, reason)

        track_table = tasks.get_kdbg(kernel_space).PoolTrackTable

        # not really an address, this is just a trick to get 
        # a 32bit number on x86 and 64bit number on x64. the
        # size is always directly before the pool table. 
        table_size = obj.Object("address", offset = 
            track_table - kernel_space.profile.get_obj_size("address"), 
            vm = kernel_space
            )

        track_table = track_table.dereference_as("address")

        if not kernel_space.is_valid_address(track_table) or table_size > 100000:
            debug.error("Cannot find the table or its size is unexpected: {0}".format(table_size))

        entries = obj.Object("Array", targetType = "_POOL_TRACKER_TABLE", 
            offset = track_table, count = table_size, 
            vm = kernel_space
            )

        if self._config.TAGS:
            tags = [tag for tag in self._config.TAGS.split(",")]
        else:
            tags = []

        for entry in entries:

            if not self._config.SHOW_FREE:
                if entry.PagedBytes == 0 and entry.NonPagedBytes == 0:
                    continue

            if not tags or entry.Key in tags:
                try:
                    (driver, reason) = knowntags[str(entry.Key).strip()]
                    if self._config.WHITELIST:
                        continue
                except KeyError:
                    (driver, reason) = ("", "")
                yield entry, driver, reason

    def render_whitelist(self, outfd, data):

        for entry, driver, reason in data:
            if str(entry.Key) == "":
                continue
            outfd.write("{0} - {1} - {2}\n".format(entry.Key, driver, reason))

    def render_text(self, outfd, data):
        
        self.table_header(outfd, [("Tag", "6"), 
                                  ("NpAllocs", "8"), 
                                  ("NpFrees", "8"), 
                                  ("NpBytes", "8"), 
                                  ("PgAllocs", "8"), 
                                  ("PgFrees", "8"), 
                                  ("PgBytes", "8"), 
                                  ("Driver", "20"), 
                                  ("Reason", "")])

        for entry, driver, reason in data:
            if str(entry.Key) == "":
                continue

            self.table_row(outfd, entry.Key, entry.NonPagedAllocs, 
                entry.NonPagedFrees, entry.NonPagedBytes, entry.PagedAllocs, 
                entry.PagedFrees, entry.PagedBytes, 
                driver, reason)

    def unified_output(self, data):
        return TreeGrid([("Tag", str),
                       ("NpAllocs", int),
                       ("NpFrees", int),
                       ("NpBytes", int),
                       ("PgAllocs", int),
                       ("PgFrees", int),
                       ("PgBytes", int),
                       ("Driver", str),
                       ("Reason", str)],
                        self.generator(data))

    def generator(self, data):
        for entry, driver, reason in data:
            if str(entry.Key) == "":
                continue

            yield (0, [str(entry.Key), 
                int(entry.NonPagedAllocs),
                int(entry.NonPagedFrees), 
                int(entry.NonPagedBytes), 
                int(entry.PagedAllocs),
                int(entry.PagedFrees),
                int(entry.PagedBytes),
                str(driver), 
                str(reason)])

#--------------------------------------------------------------------------------
# Configurable PoolScanner Plugin
#--------------------------------------------------------------------------------

class GenericPoolScan(poolscan.SinglePoolScanner):
    """Configurable pool scanner"""

class PoolPeek(common.AbstractWindowsCommand):
    """Configurable pool scanner plugin"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('TAG', short_option = 't', 
                    help = 'Pool tag to find')   
        config.add_option('MIN-SIZE', short_option = 'm', 
                    type = 'int', 
                    help = 'Minimum size of the pool to find (default: 0)', 
                    default = 0)   
        config.add_option('MAX-SIZE', short_option = 'M', 
                    type = 'int', 
                    help = 'Maximum size of the pool to find (default: 4096)', 
                    default = 4096)   
        config.add_option('PAGED', short_option = 'P', 
                    help = 'Search in paged pools (default: False)', 
                    default = False, action = "store_true")

    def calculate(self):
        addr_space = utils.load_as(self._config)

        tag = self._config.TAG

        if tag == None:
            debug.error("You must enter a --tag to find")

        minsize = self._config.MIN_SIZE
        maxsize = self._config.MAX_SIZE 
        poolsize = lambda x : x >= minsize and x <= maxsize 

        if self._config.PAGED:
            paged = True
            non_paged = False
        else:
            paged = False
            non_paged = True

        scanner = GenericPoolScan()
        scanner.checks = [ 
                ('PoolTagCheck', dict(tag = tag)),
                ('CheckPoolSize', dict(condition = poolsize)),
                ('CheckPoolType', dict(paged = paged, non_paged = non_paged)),
                ]

        for offset in scanner.scan(addr_space):
            pool = obj.Object("_POOL_HEADER", offset = offset, vm = addr_space) 
            buf = addr_space.zread(offset, minsize)
            yield pool, buf

    def render_text(self, outfd, data):
        for pool, buf in data:
            pool_alignment = obj.VolMagic(pool.obj_vm).PoolAlignment.v()
            outfd.write("Pool Header: {0:#x}, Size: {1}\n".format(
                    pool.obj_offset, 
                    pool.BlockSize * pool_alignment))
            outfd.write("{0}\n".format("\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(pool.obj_offset + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(buf)
                    ])))
            outfd.write("\n")

