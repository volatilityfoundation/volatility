# Volatility
# Copyright (c) 2012 Michael Ligh <michael.ligh@mnin.org>
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
#

import volatility.obj as obj

class _KPCROnx86(obj.CType):
    """KPCR for 32bit windows"""

    def idt_entries(self):
        for i, entry in enumerate(self.IDT.dereference()):
            yield i, entry

    def gdt_entries(self):
        for i, entry in enumerate(self.GDT.dereference()):
            yield i, entry

    def get_kdbg(self):
        """Find this CPUs KDBG. 

        Please note the KdVersionBlock pointer is NULL on
        all x64 that we've seen. Thus this technique of finding
        KDBG via KPCR is only valid for x86 profiles.
        """
        DebuggerDataList = self.KdVersionBlock.dereference_as("_DBGKD_GET_VERSION64").DebuggerDataList
    
        # DebuggerDataList is a pointer to unsigned long on x86 
        # and a pointer to unsigned long long on x64. The first 
        # dereference() dereferences the pointer, and the second 
        # dereference() dereferences the unsigned long or long long
        # as the actual KDBG address. 
        return DebuggerDataList.dereference().dereference_as("_KDDEBUGGER_DATA64")

    @property
    def ProcessorBlock(self):
        return self.PrcbData

class _KPCROnx64(_KPCROnx86):
    """KPCR for x64 windows"""
    
    def get_kdbg(self):
        return obj.NoneObject("Finding KDBG via KPCR is not possible on x64")

    @property
    def ProcessorBlock(self):
        return self.Prcb

class KPCRProfileModification(obj.ProfileModification):
    before = ['WindowsObjectClasses']

    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):

        if profile.metadata.get('memory_model', '32bit') == '32bit':
            kpcr_class = _KPCROnx86
        else:
            kpcr_class = _KPCROnx64

        profile.object_classes.update({'_KPCR': kpcr_class})