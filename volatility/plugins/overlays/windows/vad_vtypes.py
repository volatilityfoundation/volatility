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

#----------------------------------------------------------------------
# All Windows
#----------------------------------------------------------------------

class VadTraverser(obj.CType):

    ## The actual type depends on this tag value.
    tag_map = {'Vadl': '_MMVAD_LONG',
               'VadS': '_MMVAD_SHORT',
               'Vad ': '_MMVAD_LONG',
               'VadF': '_MMVAD_SHORT',
               'Vadm': '_MMVAD_LONG',
              }

    def is_valid(self):
        return (obj.CType.is_valid(self) and
                self.Start < obj.VolMagic(self.obj_vm).MaxAddress.v() and
                self.End < (obj.VolMagic(self.obj_vm).MaxAddress.v()))

    def traverse(self, visited = None, depth = 0):
        """ Traverse the VAD tree by generating all the left items,
        then the right items.

        We try to be tolerant of cycles by storing all offsets visited.
        """

        if depth > 100:
            raise RuntimeError("Vad tree too deep - something went wrong!")

        if visited == None:
            visited = set()

        ## We try to prevent loops here
        if self.obj_offset in visited:
            return

        # Find out which Vad type we need to be:
        if str(self.Tag) in self.tag_map:
            yield self.cast(self.tag_map[str(self.Tag)])

        # This tag is valid for the Root.
        elif depth and str(self.Tag) != "":
            return

        # add this node to those that have been visited
        visited.add(self.obj_offset)
 
        # traverse children
        for c in self.LeftChild.traverse(visited = visited, depth = depth + 1):
            yield c

        for c in self.RightChild.traverse(visited = visited, depth = depth + 1):
            yield c

class VadFlags(obj.CType):
    def __str__(self):
        return ", ".join(["{0}: {1}".format(name, self.m(name)) for name in sorted(self.members.keys()) if self.m(name) != 0])

class _MMVAD_FLAGS(VadFlags):
    pass

class _MMVAD_FLAGS2(VadFlags):
    pass

class _MMSECTION_FLAGS(VadFlags):
    pass

class VadFlagsModification(obj.ProfileModification):

    before = ["WindowsOverlay"]
    conditions = {"os": lambda x : x == "windows"}

    def modification(self, profile):
        profile.object_classes.update({
            '_MMVAD_FLAGS': _MMVAD_FLAGS,
            '_MMVAD_FLAGS2': _MMVAD_FLAGS2,
            '_MMSECTION_FLAGS': _MMSECTION_FLAGS,
            })

class VadTagModification(obj.ProfileModification):

    before = ["WindowsOverlay"]
    conditions = {"os": lambda x : x == "windows"}

    def modification(self, profile):

        version = (profile.metadata.get("major", 0), 
                   profile.metadata.get("minor", 0))

        model = profile.metadata.get("memory_model", "32bit")

        if model == "32bit":
            offset = -4
        else:
            offset = -12

        overlay = {
            '_MMVAD_SHORT': [ None, {
                'Tag': [offset , ['String', dict(length = 4)]],
            }],
            '_MMVAD': [ None, { 
                'Tag': [offset , ['String', dict(length = 4)]],
            }]}

        if version < (6, 2):
            overlay.update({
                '_MMVAD_LONG': [ None, {
                    'Tag': [offset , ['String', dict(length = 4)]],
                }]})

        if version >= (5, 2) and version <= (6, 1):
            overlay.update({
                '_MMADDRESS_NODE': [ None, {
                    'Tag': [offset , ['String', dict(length = 4)]],
                }]})
        elif version == (6, 2):
            overlay.update({
                '_MM_AVL_NODE': [ None, {
                    'Tag': [offset , ['String', dict(length = 4)]],
                }]})
        elif version == (6, 3):
            overlay.update({
                '_RTL_BALANCED_NODE': [ None, {
                    'Tag': [offset , ['String', dict(length = 4)]],
                }]})

        profile.merge_overlay(overlay)

#----------------------------------------------------------------------
# Windows XP 
#----------------------------------------------------------------------

class _MMVAD_SHORT_XP(VadTraverser):

    @property
    def Parent(self):
        return self.m('Parent').dereference()

    @property
    def Start(self):
        return self.StartingVpn << 12

    @property
    def End(self):
        return ((self.EndingVpn + 1) << 12) - 1

    @property
    def Length(self):
        return ((self.EndingVpn + 1) << 12) - self.Start 

    @property
    def VadFlags(self):
        return self.u.VadFlags

    @property
    def CommitCharge(self):
        return self.u.VadFlags.CommitCharge

class _MMVAD_XP(_MMVAD_SHORT_XP):

    @property
    def ControlArea(self):
        return self.m('ControlArea')

    @property
    def FileObject(self):
        return self.ControlArea.FilePointer.dereference()

class _MMVAD_LONG_XP(_MMVAD_XP):
    pass

class WinXPx86Vad(obj.ProfileModification):

    before = ["WindowsOverlay"]
    conditions = {"os": lambda x: x == "windows", 
                  "major": lambda x: x == 5, 
                  "minor": lambda x: x == 1, 
                  "memory_model": lambda x: x == "32bit"}

    def modification(self, profile):
        profile.merge_overlay({
            '_EPROCESS' : [ None, {
                'VadRoot' : [ None, ['pointer', ['_MMVAD']]],
            }]})

        profile.object_classes.update({
            '_MMVAD': _MMVAD_XP,
            '_MMVAD_SHORT': _MMVAD_SHORT_XP,
            '_MMVAD_LONG': _MMVAD_LONG_XP,
            })

#----------------------------------------------------------------------
# Windows 2003 
#----------------------------------------------------------------------

class _MMVAD_SHORT_2003(_MMVAD_SHORT_XP):

    @property
    def Parent(self):
        return obj.Object("_MMADDRESS_NODE", 
                    vm = self.obj_vm, 
                    offset = self.u1.Parent.v() & ~0x3, 
                    parent = self.obj_parent)

class _MMVAD_2003(_MMVAD_SHORT_2003):
    
    @property
    def ControlArea(self):
        return self.m('ControlArea')

    @property
    def FileObject(self):
        return self.ControlArea.FilePointer.dereference()

class _MMVAD_LONG_2003(_MMVAD_2003):
    pass

class _MM_AVL_TABLE(obj.CType):
    def traverse(self):
        for c in self.cast("_MMADDRESS_NODE").traverse():
            yield c

class Win2003x86Vad(obj.ProfileModification):

    before = ["WindowsOverlay"]
    conditions = {"os": lambda x: x == "windows", 
                  "major": lambda x: x == 5, 
                  "minor": lambda x: x == 2}

    def modification(self, profile):
        profile.object_classes.update({
            '_MMVAD': _MMVAD_2003,
            '_MMVAD_SHORT': _MMVAD_SHORT_2003,
            '_MMVAD_LONG': _MMVAD_LONG_2003,
            '_MM_AVL_TABLE': _MM_AVL_TABLE,
            '_MMADDRESS_NODE': _MMVAD_2003,
            })

#----------------------------------------------------------------------
# Windows Vista, 2008, and 7
#----------------------------------------------------------------------

class _MMVAD_VISTA(_MMVAD_SHORT_2003):
    
    @property
    def ControlArea(self):
        return self.Subsection.ControlArea

    @property
    def FileObject(self):
        return self.Subsection.ControlArea.FilePointer.dereference_as("_FILE_OBJECT")

class _MMVAD_LONG_VISTA(_MMVAD_VISTA):
    pass

class VistaVad(obj.ProfileModification):

    before = ["WindowsOverlay"]
    conditions = {"os": lambda x: x == "windows", 
                  "major": lambda x: x == 6, 
                  "minor": lambda x: (x == 0 or x == 1)}

    def modification(self, profile):
        profile.object_classes.update({
            '_MMVAD': _MMVAD_VISTA,
            '_MMVAD_SHORT': _MMVAD_SHORT_2003,
            '_MMVAD_LONG': _MMVAD_LONG_VISTA,
            '_MM_AVL_TABLE': _MM_AVL_TABLE,
            '_MMADDRESS_NODE': _MMVAD_VISTA,
            })

#----------------------------------------------------------------------
# Windows 8 and Server 2012
#----------------------------------------------------------------------

class _MM_AVL_TABLE_WIN8(obj.CType):
    def traverse(self):
        for c in self.cast("_MM_AVL_NODE").traverse():
            yield c

class _MM_AVL_NODE(VadTraverser):

    ## The actual type depends on this tag value.
    tag_map = {'Vadl': '_MMVAD',
               'VadS': '_MMVAD_SHORT',
               'Vad ': '_MMVAD',
               'VadF': '_MMVAD_SHORT',
               'Vadm': '_MMVAD',
              }

class _MMVAD_SHORT_WIN8(_MM_AVL_NODE):

    @property
    def Parent(self):
        return obj.Object("_MM_AVL_NODE", 
                    vm = self.obj_vm, 
                    offset = self.VadNode.u1.Parent.v() & ~0x3, 
                    parent = self.obj_parent)

    @property
    def Start(self):
        return self.StartingVpn << 12

    @property
    def End(self):
        return ((self.EndingVpn + 1) << 12) - 1

    @property
    def VadFlags(self):
        return self.u.VadFlags

    @property
    def CommitCharge(self):
        return self.u1.VadFlags1.CommitCharge

    @property
    def Length(self):
        return self.End - self.Start 

    @property
    def LeftChild(self):
        return self.VadNode.LeftChild

    @property
    def RightChild(self):
        return self.VadNode.RightChild

class _MMVAD_WIN8(_MM_AVL_NODE):

    @property
    def Parent(self):
        return self.Core.Parent

    @property
    def Start(self):
        return self.Core.Start
    
    @property
    def End(self):
        return self.Core.End

    @property
    def VadFlags(self):
        return self.Core.VadFlags
    
    @property
    def CommitCharge(self):
        return self.Core.CommitCharge

    @property
    def ControlArea(self):
        return self.Subsection.ControlArea

    @property
    def FileObject(self):
        return self.Subsection.ControlArea.FilePointer.dereference_as("_FILE_OBJECT")

    @property
    def Length(self):
        return self.End - self.Start 

    @property
    def LeftChild(self):
        return self.Core.LeftChild

    @property
    def RightChild(self):
        return self.Core.RightChild

class Win8Vad(obj.ProfileModification):

    before = ["WindowsOverlay"]
    conditions = {"os": lambda x: x == "windows", 
                  "major": lambda x: x == 6, 
                  "minor": lambda x: x == 2}

    def modification(self, profile):
        profile.object_classes.update({
            '_MMVAD': _MMVAD_WIN8,
            '_MMVAD_SHORT': _MMVAD_SHORT_WIN8,
            '_MM_AVL_TABLE': _MM_AVL_TABLE_WIN8,
            '_MM_AVL_NODE': _MM_AVL_NODE,
            })

#----------------------------------------------------------------------
# Windows 8.1 and Server 2012 R2
#----------------------------------------------------------------------

class _RTL_AVL_TREE(obj.CType):
    def traverse(self):
        for x in self.Root.traverse():
            yield x

class _RTL_BALANCED_NODE(VadTraverser):

    ## The actual type depends on this tag value.
    tag_map = {'Vadl': '_MMVAD',
               'VadS': '_MMVAD_SHORT',
               'Vad ': '_MMVAD',
               'VadF': '_MMVAD_SHORT',
               'Vadm': '_MMVAD',
              }

    @property
    def LeftChild(self):
        return self.Left

    @property 
    def RightChild(self):
        return self.Right

class _MMVAD_SHORT_WIN81(_RTL_BALANCED_NODE):

    @property
    def Parent(self):
        return obj.Object("_RTL_BALANCED_NODE", 
                    vm = self.obj_vm, 
                    offset = self.VadNode.ParentValue.v() & ~0x3, 
                    parent = self.obj_parent)

    @property
    def Start(self):
        return self.StartingVpn << 12

    @property
    def End(self):
        return ((self.EndingVpn + 1) << 12) - 1

    @property
    def VadFlags(self):
        return self.u.VadFlags

    @property
    def CommitCharge(self):
        return self.u1.VadFlags1.CommitCharge

    @property
    def Length(self):
        return self.End - self.Start 

    @property
    def LeftChild(self):
        return self.VadNode.Left

    @property
    def RightChild(self):
        return self.VadNode.Right

class _MMVAD_WIN81(_MMVAD_SHORT_WIN81):

    @property
    def Parent(self):
        return self.Core.Parent

    @property
    def Start(self):
        return self.Core.Start
    
    @property
    def End(self):
        return self.Core.End

    @property
    def VadFlags(self):
        return self.Core.VadFlags
    
    @property
    def CommitCharge(self):
        return self.Core.CommitCharge

    @property
    def ControlArea(self):
        return self.Subsection.ControlArea

    @property
    def FileObject(self):
        return self.Subsection.ControlArea.FilePointer.dereference_as("_FILE_OBJECT")

    @property
    def Length(self):
        return self.End - self.Start 

    @property
    def LeftChild(self):
        return self.Core.LeftChild

    @property
    def RightChild(self):
        return self.Core.RightChild

class Win81Vad(obj.ProfileModification):

    before = ["WindowsOverlay"]
    conditions = {"os": lambda x: x == "windows", 
                  "major": lambda x: x == 6, 
                  "minor": lambda x: x == 3}

    def modification(self, profile):
        profile.object_classes.update({
            '_MMVAD': _MMVAD_WIN81,
            '_MMVAD_SHORT': _MMVAD_SHORT_WIN81,
            '_RTL_AVL_TREE': _RTL_AVL_TREE,
            '_RTL_BALANCED_NODE': _RTL_BALANCED_NODE,
            })
