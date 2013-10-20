# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
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

import volatility.obj as obj

hibernate_vtypes = {
    '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
    'NextTable' : [ 0x4, ['unsigned long']],
    'EntryCount' : [ 0xc, ['unsigned long']],
} ],
    '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, {
    'StartPage' : [ 0x4, ['unsigned long']],
    'EndPage' : [ 0x8, ['unsigned long']],
} ],
    '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
    'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
    'RangeTable': [ 0x10, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
} ],
'_IMAGE_XPRESS_HEADER' : [  0x20 , {
  'u09' : [ 0x9, ['unsigned char']],
  'u0A' : [ 0xA, ['unsigned char']],
  'u0B' : [ 0xB, ['unsigned char']],
} ]
}

hibernate_vistasp01_vtypes = {
  '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
    'NextTable' : [ 0x4, ['unsigned long']],
    'EntryCount' : [ 0xc, ['unsigned long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
    'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
    'RangeTable': [ 0x10, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
} ],
}

class HiberVistaSP01x86(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x <= 6001,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(hibernate_vistasp01_vtypes)


hibernate_vistasp2_vtypes = {
  '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
    'NextTable' : [ 0x4, ['unsigned long']],
    'EntryCount' : [ 0x8, ['unsigned long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x8, {
    'StartPage' : [ 0x0, ['unsigned long']],
    'EndPage' : [ 0x4, ['unsigned long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
    'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
    'RangeTable': [ 0xc, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
} ],
}

class HiberVistaSP2x86(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x == 6002,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(hibernate_vistasp2_vtypes)

hibernate_win7_vtypes = {
  '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
    'NextTable' : [ 0x0, ['unsigned long']],
    'EntryCount' : [ 0x4, ['unsigned long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x8, {
    'StartPage' : [ 0x0, ['unsigned long']],
    'EndPage' : [ 0x4, ['unsigned long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
    'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
    'RangeTable': [ 0x8, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
} ],
}

class HiberWin7SP01x86(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'build': lambda x: x <= 7601,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(hibernate_win7_vtypes)


hibernate_win7_x64_vtypes = {
  '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
    'NextTable' : [ 0x0, ['unsigned long long']],
    'EntryCount' : [ 0x8, ['unsigned long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, {
    'StartPage' : [ 0x0, ['unsigned long long']],
    'EndPage' : [ 0x8, ['unsigned long long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
    'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
    'RangeTable': [ 0x10, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
} ],
}

class HiberWin7SP01x64(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'build': lambda x: x <= 7601,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(hibernate_win7_x64_vtypes)

hibernate_x64_vtypes = {
  '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x20, {
    'NextTable' : [ 0x8, ['unsigned long long']],
    'EntryCount' : [ 0x14, ['unsigned long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x20, {
    'StartPage' : [ 0x8, ['unsigned long long']],
    'EndPage' : [ 0x10, ['unsigned long long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY' : [ 0x40, {
    'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
    'RangeTable': [ 0x20, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
} ],
}

class HiberWin2003x64(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2,
                  'build': lambda x: x <= 3791,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(hibernate_x64_vtypes)

class HiberVistaSP01x64(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x <= 6001,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(hibernate_x64_vtypes)

hibernate_vistaSP2_x64_vtypes = {
  '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x18, {
    'NextTable' : [ 0x8, ['unsigned long long']],
    'EntryCount' : [ 0x10, ['unsigned long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, {
    'StartPage' : [ 0x0, ['unsigned long long']],
    'EndPage' : [ 0x8, ['unsigned long long']],
} ],
  '_PO_MEMORY_RANGE_ARRAY' : [ 0x28, {
    'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
    'RangeTable': [ 0x18, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
} ],
}

class HiberVistaSP2x64(obj.ProfileModification):
    before = ['WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'build': lambda x: x == 6002,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(hibernate_vistaSP2_x64_vtypes)
