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

"""
@author:       Jamie Levy (Gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie.levy@gmail.com

This file provides support for Windows 2003.
"""

#pylint: disable-msg=C0111

import windows
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.obj as obj

class _MM_AVL_TABLE(obj.CType):
    def traverse(self):
        """
        This is a hack to get around the fact that _MM_AVL_TABLE.BalancedRoot (an _MMADDRESS_NODE) doesn't
        work the same way as the other _MMADDRESS_NODEs. In particular, we want _MMADDRESS_NODE to behave
        like _MMVAD, and all other _MMADDRESS_NODEs have a Vad, VadS, Vadl tag etc, but _MM_AVL_TABLE.BalancedRoot
        does not. So we can't reference self.BalancedRoot.RightChild here because self.BalancedRoot will be None
        due to the fact that there is not a valid VAD tag at self.BalancedRoot.obj_offset - 4 (as _MMVAD expects).

        We want to start traversing from self.BalancedRoot.RightChild. The self.BalancedRoot.LeftChild member
        will always be 0. However, we can't call get_obj_offset("_MMADDRESS_NODE", "RightChild") or it will 
        result in a TypeError: __new__() takes exactly 5 non-keyword arguments (4 given). Therefore, we hard-code
        the offset to the RightChild and treat it as a pointer to the first real _MMADDRESS_NODE. 

        Update: hard-coding the offset to RightChild breaks x64 (since the offset is 8 on x86 and 16 on x64). 
        Thus to fix the vad plugins for x64 we assume that the offset of RightChild in _MMVAD_SHORT is the 
        same as the offset of RightChild in _MMADDRESS_NODE. We can call get_obj_offset on _MMVAD_SHORT since
        it isn't in the _MMVAD factory like _MMADDRESS_NODE; and we won't get the above TypeError. 
        """
        right_child_offset = self.obj_vm.profile.get_obj_offset("_MMVAD_SHORT", "RightChild")

        rc = obj.Object("Pointer", vm = self.obj_vm, offset = self.obj_offset + right_child_offset)

        node = obj.Object('_MMADDRESS_NODE', vm = self.obj_vm, offset = rc.v(), parent = self.obj_parent)

        for c in node.traverse():
            yield c

class _MMVAD_SHORT(windows._MMVAD_SHORT):

    @property
    def Parent(self):
        """
        Return the Vad's parent node, being sure to chop off the 
        lower 3 bits, because _MMADDRESS_NODE.u1.Parent is a 
        packed union with _MMADDRESS_NODE.u1.Balanced. We do not
        want the Balanced part of the value. 

        Not chopping off these 3 bits is the reason why our vadtree
        plugin didn't work since introduction of profiles other 
        than Windows XP. 
        """
        return obj.Object("_MMADDRESS_NODE", vm = self.obj_vm, 
                    offset = self.u1.Parent.v() & ~0x3, 
                    parent = self.obj_parent)

class _MMVAD_LONG(_MMVAD_SHORT):
    pass

class Win2003MMVad(obj.ProfileModification):
    before = ['WindowsOverlay', 'WindowsObjectClasses']

    def check(self, profile):
        m = profile.metadata
        return (m.get('os', None) == 'windows' and
                (m.get('major') > 5 or (m.get('major') == 5 and m.get('minor') >= 2)))

    def modification(self, profile):
        profile.object_classes.update({'_MM_AVL_TABLE': _MM_AVL_TABLE,
                                       '_MMADDRESS_NODE': windows._MMVAD,
                                       '_MMVAD_SHORT': _MMVAD_SHORT,
                                       '_MMVAD_LONG': _MMVAD_LONG})

class Win2003x86Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x2)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0xff)]],
                                        }]}
        profile.merge_overlay(overlay)

class Win2003x64Hiber(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}
    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'HibrProcPage' : [ None, ['VolatilityMagic', dict(value = 0x2)]],
                        'HibrEntryCount' : [ None, ['VolatilityMagic', dict(value = 0x7f)]],
                                        }]}
        profile.merge_overlay(overlay)

class Win2003KDBG(windows.AbstractKDBGMod):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x >= 2}
    kdbgsize = 0x318

class Win2003SP0x86DTB(obj.ProfileModification):
    # Make sure we apply after the normal Win2003 DTB
    before = ['WindowsOverlay', 'Win2003x86DTB']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2,
                  'build': lambda x: x == 3789}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'DTBSignature': [ None, ['VolatilityMagic', dict(value = "\x03\x00\x1b\x00")]]}
                                        ]}
        profile.merge_overlay(overlay)

class Win2003x86DTB(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'DTBSignature': [ None, ['VolatilityMagic', dict(value = "\x03\x00\x1e\x00")]]}
                                        ]}
        profile.merge_overlay(overlay)

class Win2003x64DTB(obj.ProfileModification):
    before = ['WindowsOverlay', 'Windows64Overlay']
    conditions = {'os': lambda x : x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                        'DTBSignature': [ None, ['VolatilityMagic', dict(value = "\x03\x00\x2e\x00")]]}
                                        ]}
        profile.merge_overlay(overlay)

class EThreadCreateTime(obj.ProfileModification):
    before = ['WindowsOverlay']

    def check(self, profile):
        m = profile.metadata
        return (m.get('os', None) == 'windows' and
                ((m.get('major', 0) == 5 and m.get('minor', 0) >= 2) or
                 m.get('major', 0) >= 6) and
                 profile.__class__.__name__ != 'Win2003SP0x86')

    def modification(self, profile):
        overlay = {'_ETHREAD': [ None, {
                        'CreateTime' : [ None, ['WinTimeStamp', {}]]}
                                ]}
        profile.merge_overlay(overlay)

class Win2003SP0x86(obj.Profile):
    """ A Profile for Windows 2003 SP0 x86 """
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    # FIXME: 2003's build numbers didn't differentiate between SP0 and SP1/2
    # despite there being a large change. As such we fake a special build number
    # for 2003 SP0 to help us differentiate it
    _md_build = 3789
    _md_memory_model = '32bit'
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp0_x86_vtypes'

class Win2003SP1x86(obj.Profile):
    """ A Profile for Windows 2003 SP1 x86 """
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    _md_build = 3790
    _md_memory_model = '32bit'
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp1_x86_vtypes'

class Win2003SP2x86(obj.Profile):
    """ A Profile for Windows 2003 SP2 x86 """
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    # This is a fake build number. See the comment in Win2003SP0x86
    _md_build = 3791 
    _md_memory_model = '32bit'
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp2_x86_vtypes'

class Win2003SP1x64(obj.Profile):
    """ A Profile for Windows 2003 SP1 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    _md_build = 3790
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp1_x64_vtypes'

class Win2003SP2x64(obj.Profile):
    """ A Profile for Windows 2003 SP2 x64 """
    _md_memory_model = '64bit'
    _md_os = 'windows'
    _md_major = 5
    _md_minor = 2
    # This is a fake build number. See the comment in Win2003SP0x86
    _md_build = 3791
    _md_vtype_module = 'volatility.plugins.overlays.windows.win2003_sp2_x64_vtypes'

class WinXPSP1x64(Win2003SP1x64):
    """ A Profile for Windows XP SP1 x64 """

class WinXPSP2x64(Win2003SP2x64):
    """ A Profile for Windows XP SP2 x64 """

