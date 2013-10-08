# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
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

import copy
import volatility.obj as obj
import volatility.plugins.overlays.windows.windows as windows

# File-wide pylint message disable because we have a few situations where we access structs starting _
#pylint: disable-msg=W0212

class Pointer64Decorator(object):
    def __init__(self, f):
        self.f = f

    def __call__(self, name, typeList, typeDict = None):
        if len(typeList) and typeList[0] == 'pointer64':
            typeList = copy.deepcopy(typeList)
            typeList[0] = 'pointer'
        return self.f(name, typeList, typeDict)

class _EX_FAST_REF(windows._EX_FAST_REF):
    MAX_FAST_REF = 15

class ExFastRefx64(obj.ProfileModification):
    before = ['WindowsOverlay', 'WindowsObjectClasses']
    conditions = {'os': lambda x : x == 'windows',
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.object_classes.update({'_EX_FAST_REF': _EX_FAST_REF})


class Windows64Overlay(obj.ProfileModification):
    before = ['WindowsOverlay', 'WindowsObjectClasses']
    conditions = {'memory_model': lambda x: x == '64bit',
                  'os': lambda x: x == 'windows'}

    def modification(self, profile):
        profile.merge_overlay({'VOLATILITY_MAGIC': [ 0x0, {
                                    'PoolAlignment': [ 0x0, ['VolatilityMagic', dict(value = 16)] ],
                                    'KUSER_SHARED_DATA': [ 0x0, ['VolatilityMagic', dict(value = 0xFFFFF78000000000)]]
                                                           }
                                                    ]})
        # This is the location of the MMVAD type which controls how to parse the
        # node. It is located before the structure.
        profile.merge_overlay({'_MMVAD_SHORT': [None, {
                                    'Tag' : [-12, None],
                                  }],
                               '_MMVAD_LONG' : [None, {
                                    'Tag' : [-12, None],
                                                       }]
                               })
        profile.vtypes["_IMAGE_NT_HEADERS"] = profile.vtypes["_IMAGE_NT_HEADERS64"]

        profile.merge_overlay({'_DBGKD_GET_VERSION64' : [  None, {
            'DebuggerDataList' : [ None, ['pointer', ['unsigned long long']]],
            }]})

        # In some auto-generated vtypes, the DTB is an array of 2 unsigned longs 
        # (for x86) or an array of 2 unsigned long long (for x64). We have an overlay
        # in windows.windows_overlay which sets the DTB to a single unsigned long,
        # but we do not want that bleeding through to the x64 profiles. Instead we 
        # want the x64 DTB to be a single unsigned long long. 
        profile.merge_overlay({'_KPROCESS' : [ None, {
            'DirectoryTableBase' : [ None, ['unsigned long long']],
            }]})

        # Note: the following method of profile modification is strongly discouraged
        #
        # Nasty hack because pointer64 has a special structure,
        # and therefore can't just be instantiated in object_classes
        # using profile.object_classes.update({'pointer64': obj.Pointer})
        profile._list_to_type = Pointer64Decorator(profile._list_to_type)
