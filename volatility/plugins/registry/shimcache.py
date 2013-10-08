# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie.levy@gmail.com>
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
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie.levy@gmail.com
@organization: Volatility Foundation
"""

import volatility.plugins.registry.registryapi as registryapi
import volatility.debug as debug
import volatility.utils as utils
import volatility.obj as obj
import volatility.commands as commands
import volatility.addrspace as addrspace

# Structures taken from the ShimCache Whitepaper: https://blog.mandiant.com/archives/2459

#### SHIMRECS ####

shimrecs_type_xp = {
    'ShimRecords' : [ None, {
        'Magic' : [ 0x0, ['unsigned int']], #0xDEADBEEF
        'NumRecords' : [ 0x8, ['short']],
        'Entries' : [0x190, ['array', lambda x: x.NumRecords, ['AppCompatCacheEntry']]],
    } ],
}

shimrecs_type_2003vista = {
    'ShimRecords' : [ None, {
        'Magic' : [ 0x0, ['unsigned int']], #0xBADC0FFE
        'NumRecords' : [ 0x4, ['int']],
        'Entries' : [0x8, ['array', lambda x: x.NumRecords, ['AppCompatCacheEntry']]],
    } ],
}

shimrecs_type_win7 = {
    'ShimRecords' : [ None, {
        'Magic' : [ 0x0, ['unsigned int']], #0xBADC0FFE
        'NumRecords' : [ 0x4, ['int']],
        'Entries' : [0x80, ['array', lambda x: x.NumRecords, ['AppCompatCacheEntry']]],
    } ],
}

#### APPCOMPAT TYPES ####

appcompat_type_xp_x86 = {
    'AppCompatCacheEntry' : [ 0x228, {
        'Path' : [ 0x0, ['NullString', dict(length = 0x208, encoding = 'utf8')]],
        'LastModified' : [ 0x210, ['WinTimeStamp', dict(is_utc = True)]],
        'FileSize': [0x218, ['long long']],
        'LastUpdate' : [ 0x220, ['WinTimeStamp', dict(is_utc = True)]],
    } ],
}

appcompat_type_2003_x86 = {
    'AppCompatCacheEntry' : [ 0x18, {
        'Length' : [ 0x0, ['unsigned short']],
        'MaximumLength' : [0x2, ['unsigned short']],
        'PathOffset' : [ 0x4, ['unsigned int']],
        'LastModified' : [ 0x8, ['WinTimeStamp', dict(is_utc = True)]],
        'FileSize': [0x10, ['_LARGE_INTEGER']],
    } ],
}

appcompat_type_vista_x86 = {
    'AppCompatCacheEntry' : [ 0x18, {
        'Length' : [ 0x0, ['unsigned short']],
        'MaximumLength' : [0x2, ['unsigned short']],
        'PathOffset' : [ 0x4, ['unsigned int']],
        'LastModified' : [ 0x8, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x10, ['unsigned int']],
        'Flags' : [0x14, ['unsigned int']],
    } ],
}

appcompat_type_win7_x86 = {
    'AppCompatCacheEntry' : [ 0x20, {
        'Length' : [ 0x0, ['unsigned short']],
        'MaximumLength' : [0x2, ['unsigned short']],
        'PathOffset' : [ 0x4, ['unsigned int']],
        'LastModified' : [ 0x8, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x10, ['unsigned int']],
        'ShimFlags' : [0x14, ['unsigned int']],
        'BlobSize' : [0x18, ['unsigned int']],
        'BlobOffset' : [0x1c, ['unsigned int']],
    } ],
}

appcompat_type_2003_x64 = {
    'AppCompatCacheEntry' : [ 0x20, {
        'Length' : [ 0x0, ['unsigned short']],
        'MaximumLength' : [0x2, ['unsigned short']],
        'PathOffset' : [ 0x8, ['unsigned long long']],
        'LastModified' : [ 0x10, ['WinTimeStamp', dict(is_utc = True)]],
        'FileSize': [0x18, ['_LARGE_INTEGER']],
    } ],
}

appcompat_type_vista_x64 = {
    'AppCompatCacheEntry' : [ 0x20, {
        'Length' : [ 0x0, ['unsigned short']],
        'MaximumLength' : [0x2, ['unsigned short']],
        'PathOffset' : [ 0x8, ['unsigned int']],
        'LastModified' : [ 0x10, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x18, ['unsigned int']],
        'Flags' : [0x1c, ['unsigned int']],
    } ],
}

appcompat_type_win7_x64 = {
    'AppCompatCacheEntry' : [ 0x30, {
        'Length' : [ 0x0, ['unsigned short']],
        'MaximumLength' : [0x2, ['unsigned short']],
        'PathOffset' : [ 0x8, ['unsigned long long']],
        'LastModified' : [ 0x10, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x18, ['unsigned int']],
        'ShimFlags' : [0x1c, ['unsigned int']],
        'BlobSize' : [0x20, ['unsigned long long']],
        'BlobOffset' : [0x28, ['unsigned long long']],
    } ],
}

class ShimCacheTypesXPx86(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 1,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(shimrecs_type_xp)
        profile.vtypes.update(appcompat_type_xp_x86)


class ShimCacheTypes2003x86(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(shimrecs_type_2003vista)
        profile.vtypes.update(appcompat_type_2003_x86)

class ShimCacheTypesVistax86(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(shimrecs_type_2003vista)
        profile.vtypes.update(appcompat_type_vista_x86)

class ShimCacheTypesWin7x86(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(shimrecs_type_win7)
        profile.vtypes.update(appcompat_type_win7_x86)

class ShimCacheTypes2003x64(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(shimrecs_type_2003vista)
        profile.vtypes.update(appcompat_type_2003_x64)

class ShimCacheTypesVistax64(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(shimrecs_type_2003vista)
        profile.vtypes.update(appcompat_type_vista_x64)

class ShimCacheTypesWin7x64(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(shimrecs_type_win7)
        profile.vtypes.update(appcompat_type_win7_x64)


class ShimCache(commands.Command):
    """Parses the Application Compatibility Shim Cache registry key"""

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'unknown').lower() == 'windows'

    def remove_unprintable(self, item):
        return ''.join([str(c) for c in item if (ord(c) > 31 or ord(c) == 9) and ord(c) <= 126])

    def calculate(self):
        addr_space = utils.load_as(self._config)
        regapi = registryapi.RegistryApi(self._config)
        regapi.reset_current()
        currentcs = regapi.reg_get_currentcontrolset()
        if currentcs == None:
            currentcs = "ControlSet001"

        version = (addr_space.profile.metadata.get('major', 0),
                   addr_space.profile.metadata.get('minor', 0))
        xp = False

        if version <= (5, 1):
            key = currentcs + '\\' + "Control\\Session Manager\\AppCompatibility"
            xp = True
        else:
            key = currentcs + '\\' + "Control\\Session Manager\\AppCompatCache"

        data_raw = regapi.reg_get_value('system', key, "AppCompatCache")
        if data_raw == None or len(data_raw) < 0x1c:
            debug.warning("No ShimCache data found")
            return

        bufferas = addrspace.BufferAddressSpace(self._config, data = data_raw)
        shimdata = obj.Object("ShimRecords", offset = 0, vm = bufferas)
        if shimdata == None:
            debug.warning("No ShimCache data found")
            return

        for e in shimdata.Entries:
            if xp:
                yield e.Path, e.LastModified, e.LastUpdate
            else:
                yield self.remove_unprintable(bufferas.read(int(e.PathOffset), int(e.Length))), e.LastModified, None

    def render_text(self, outfd, data):
        first = True
        for path, lm, lu in data:
            if lu:
                if first:
                    self.table_header(outfd, [("Last Modified", "30"),
                                              ("Last Update", "30"),
                                              ("Path", ""),
                                             ])
                    first = False
                outfd.write("{0:30} {1:30} {2}\n".format(lm, lu, path))
            else:
                if first:
                    self.table_header(outfd, [("Last Modified", "30"),
                                              ("Path", ""),
                                             ])
                    first = False
                outfd.write("{0:30} {1}\n".format(lm, path))
