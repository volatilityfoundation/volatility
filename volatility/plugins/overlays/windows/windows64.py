# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
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

import copy
import volatility.obj as obj
import volatility.plugins.overlays.windows.windows as windows
import volatility.plugins.overlays.windows.pe_vtypes as pe_vtypes
import volatility.registry as registry
import volatility.debug as debug

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

class LIST_ENTRY32(windows._LIST_ENTRY):
    """the LDR member is an unsigned long not a Pointer as regular LIST_ENTRY"""
    def get_next_entry(self, member):
        return obj.Object("LIST_ENTRY32", offset = self.m(member).v(), vm = self.obj_vm)

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
                                    'KUSER_SHARED_DATA': [ 0x0, ['VolatilityMagic', dict(value = 0xFFFFF78000000000)]],
                                                           }
                                                    ]})
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

class WinPeb32(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit'}

    before = ['WinPEVTypes', 'WinPEx64VTypes', 'WinPEObjectClasses', 'WindowsObjectClasses']

    def cast_as_32bit(self, source_vtype):
        vtype = copy.copy(source_vtype)
        # the members of the structure
        members = vtype[1]

        mapping = {
            "pointer": "pointer32",
            "_UNICODE_STRING": "_UNICODE32_STRING",
            "_LIST_ENTRY": "LIST_ENTRY32",
        }

        for name, member in members.items():
            datatype = member[1][0]

            if datatype in mapping:
                member[1][0] = mapping[datatype]

        return vtype

    def modification(self, profile):
        profiles = registry.get_plugin_classes(obj.Profile)
        meta = profile.metadata

        # find the equivalent 32-bit profile to this 64-bit profile.
        # the prof._md_build + 1 accounts for a poor decision we made
        # a while back where we added + 1 to the build number for 
        # server-based profiles as a method to distinguish between 
        # client vs server in a plugin. 
        profile_32bit = None
        for prof in profiles.values():
            if (prof._md_os == "windows" and
                            prof._md_major == meta.get("major") and
                            prof._md_minor == meta.get("minor") and
                            ((prof._md_build == meta.get("build")) or (prof._md_build + 1 == meta.get("build"))) and
                            prof._md_memory_model == "32bit"):

                profile_32bit = prof()
                break

        if profile_32bit == None:
            debug.warning("Cannot find a 32-bit equivalent profile. The "\
                "WoW64 plugins (dlllist, ldrmodules, etc) may not work.")
            return

        profile.vtypes.update({
            "_PEB32_LDR_DATA": self.cast_as_32bit(profile_32bit.vtypes["_PEB_LDR_DATA"]),
            "_LDR32_DATA_TABLE_ENTRY": self.cast_as_32bit(profile_32bit.vtypes["_LDR_DATA_TABLE_ENTRY"]),
            '_UNICODE32_STRING': self.cast_as_32bit(profile_32bit.vtypes["_UNICODE_STRING"]),
        })

        profile.object_classes.update({
            "_LDR32_DATA_TABLE_ENTRY": pe_vtypes._LDR_DATA_TABLE_ENTRY,
            "_UNICODE32_STRING": windows._UNICODE_STRING,
            "LIST_ENTRY32": LIST_ENTRY32,
        })

        profile.merge_overlay({
            '_PEB32': [None, {
                'Ldr': [None, ['pointer32', ['_PEB32_LDR_DATA']]],
        }]})