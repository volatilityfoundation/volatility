# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2012 Michael Ligh <michael.ligh@mnin.org>
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
        all KPCR structures except the one for the first CPU. 
        In some cases on x64, even the first CPU has a NULL
        KdVersionBlock, so this is really a hit-or-miss. 
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

    @property
    def ProcessorBlock(self):
        return self.Prcb

    @property
    def IDT(self):
        return self.IdtBase

    @property
    def GDT(self):
        return self.GdtBase 

class KPCRProfileModification(obj.ProfileModification):
    before = ['WindowsObjectClasses']

    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):

        if profile.metadata.get('memory_model', '32bit') == '32bit':
            kpcr_class = _KPCROnx86
        else:
            kpcr_class = _KPCROnx64

        profile.object_classes.update({'_KPCR': kpcr_class})

        profile.merge_overlay({
            '_KPRCB': [ None, { 
            'VendorString': [ None, ['String', dict(length = 13)]], 
            }]})
