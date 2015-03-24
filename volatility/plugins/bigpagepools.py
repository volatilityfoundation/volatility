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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

import volatility.plugins.common as common
import volatility.utils as utils 
import volatility.win32.tasks as tasks
import volatility.obj as obj
import volatility.debug as debug
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

#--------------------------------------------------------------------------------
# Profile Modifications 
#--------------------------------------------------------------------------------

class PoolTrackTypeOverlay(obj.ProfileModification):

    # This ensures _POOL_DESCRIPTOR will be available, 
    # so we can copy the PoolType enumeration
    before = ['WindowsVTypes']

    # PoolType didn't exist until Vista 
    conditions = {'os': lambda x: x == 'windows', 
        'major': lambda x : x >= 6}

    def modification(self, profile):
        profile.merge_overlay({
            '_POOL_TRACKER_BIG_PAGES': [ None, {
            'PoolType': [ None, profile.vtypes['_POOL_DESCRIPTOR'][1]['PoolType'][1]],
            'Key': [ None, ['String', dict(length = 4)]], 
             }],
        })

#--------------------------------------------------------------------------------
# Volatility Magic 
#--------------------------------------------------------------------------------

class BigPageTableMagic(obj.ProfileModification):
    """Determine the distance to the big page pool trackers"""    

    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):
        m = profile.metadata 

        distance_map = {
            (5, 1, '32bit') : [8, 12], 
            (5, 2, '32bit') : [24, 28],
            (5, 2, '64bit') : [48, 56],
            (6, 0, '32bit') : [20, 24], 
            (6, 0, '64bit') : [40, 48],
            (6, 1, '32bit') : [20, 24], 
            (6, 1, '64bit') : [40, 48],
            (6, 2, '32bit') : [92, 88],
            (6, 2, '64bit') : [-5200, -5224], 
            (6, 3, '32bit') : [116, 120],
        }

        version = (m.get('major', 0), m.get('minor', 0), m.get('memory_model', '32bit'))
        distance = [distance_map.get(version)]

        if distance == [None]:
            if version == (6, 3, '64bit'):
                if m.get('build', 0) == 9601:
                    distance = [[-5192, -5200], [-5224, -5232]]
                else:
                    distance = [[-5200, -5176]]

        profile.merge_overlay({
            'VOLATILITY_MAGIC': [ None, {
            'BigPageTable': [ 0, [
                'BigPageTable', dict(distance = distance)]],
            }]})

        profile.object_classes.update({'BigPageTable': BigPageTable})

class BigPageTable(obj.VolatilityMagic):
    """Find the directory of big page pools"""

    def __init__(self, *args, **kwargs):
        # Remove the value kwarg since overlaying one 
        # on the other would give the value precedence
        kwargs.pop('value', None)

        # Save the distance argument for later
        self.distance = kwargs.get('distance', None)
        obj.VolatilityMagic.__init__(self, *args, **kwargs)

    def generate_suggestions(self):
        """The nt!PoolBigPageTable and nt!PoolBigPageTableSize
        are found relative to nt!PoolTrackTable"""

        track_table = tasks.get_kdbg(self.obj_vm).PoolTrackTable

        for pair in self.distance:
            table_base = obj.Object("address", 
                offset = track_table - pair[0], 
                vm = self.obj_vm)

            table_size = obj.Object("address", 
                offset = track_table - pair[1], 
                vm = self.obj_vm)

            if table_size != 0 and self.obj_vm.is_valid_address(table_base):
                break

        debug.debug("Distance Map: {0}".format(repr(self.distance)))
        debug.debug("PoolTrackTable: {0:#x}".format(track_table))
        debug.debug("PoolBigPageTable: {0:#x} => {1:#x}".format(table_base.obj_offset, table_base))
        debug.debug("PoolBigPageTableSize: {0:#x} => {1:#x}".format(table_size.obj_offset, table_size))
        yield table_base, table_size

#--------------------------------------------------------------------------------
# Big Page Pool Scanner
#--------------------------------------------------------------------------------

class BigPagePoolScanner(object):
    """Scanner for big page pools"""

    def __init__(self, kernel_space):
        self.kernel_space = kernel_space

    def scan(self, tags = []):
        """
        Scan for the pools by tag. 

        @param tags: a list of pool tags to scan for, 
        or empty for scanning for all tags.
        """

        (table_base, table_size) = \
            obj.VolMagic(self.kernel_space).BigPageTable.v()

        pools = obj.Object('Array', targetType = '_POOL_TRACKER_BIG_PAGES', 
            offset = table_base, 
            count = table_size, vm = self.kernel_space
            )

        for pool in pools:
            if pool.Va.is_valid():
                if not tags or pool.Key in tags:
                    yield pool

#--------------------------------------------------------------------------------
# BigPools Plugin
#--------------------------------------------------------------------------------

class BigPools(common.AbstractWindowsCommand):
    """Dump the big page pools using BigPagePoolScanner"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('TAGS', short_option = 't', help = 'Pool tag to find')

    def calculate(self):

        kernel_space = utils.load_as(self._config)

        if self._config.TAGS:
            tags = [tag for tag in self._config.TAGS.split(",")]
        else:
            tags = []

        for pool in BigPagePoolScanner(kernel_space).scan(tags):
            yield pool

    def unified_output(self, data):
        return TreeGrid([("Allocation", Address),
                       ("Tag", str),
                       ("PoolType", str),
                       ("NumberOfBytes", str)],
                        self.generator(data))

    def generator(self, data):
        for entry in data:

            # Not available until Vista 
            pool_type = ""
            if hasattr(entry, 'PoolType'):
                pool_type = entry.PoolType
    
            # Not available until Vista 
            num_bytes = ""
            if hasattr(entry, 'NumberOfBytes'):
                num_bytes = hex(entry.NumberOfBytes)

            yield (0, [Address(entry.Va), str(entry.Key), str(pool_type), str(num_bytes)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Allocation", "[addrpad]"), 
                                  ("Tag", "8"), 
                                  ("PoolType", "26"), 
                                  ("NumberOfBytes", "")])

        for entry in data:
            # Not available until Vista 
            pool_type = ""
            if hasattr(entry, 'PoolType'):
                pool_type = entry.PoolType
    
            # Not available until Vista 
            num_bytes = ""
            if hasattr(entry, 'NumberOfBytes'):
                num_bytes = hex(entry.NumberOfBytes)

            self.table_row(outfd, entry.Va, entry.Key, pool_type, num_bytes)
