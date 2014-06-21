# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
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
import volatility.poolscan as poolscan
import volatility.plugins.common as common
import volatility.plugins.gui.windowstations as windowstations

class PoolScanAtom(poolscan.PoolScanner):
    """Pool scanner for atom tables"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.pooltag = "AtmT"
        self.struct_name = "_RTL_ATOM_TABLE"

        self.checks = [ 
               ('CheckPoolSize', dict(condition = lambda x: x >= 200)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ]

        ## Note: all OS after XP, there are an extra 8 bytes (for 32-bit)
        ## or 16 bytes (for 64-bit) between the _POOL_HEADER and _RTL_ATOM_TABLE. 
        ## This is variable length structure, so we can't use the bottom-up
        ## approach as we do with other object scanners - because the size of an
        ## _RTL_ATOM_TABLE differs depending on the number of hash buckets. 

        profile = self.address_space.profile

        build = (profile.metadata.get('major', 0),
                 profile.metadata.get('minor', 0))

        if profile.metadata.get('memory_model', '32bit') == '32bit':
            fixup = 8 if build > (5, 1) else 0
        else:
            fixup = 16 if build > (5, 1) else 0

        self.padding = fixup

class AtomScan(common.AbstractScanCommand):
    """Pool scanner for atom tables"""

    scanners = [PoolScanAtom]

    def __init__(self, config, *args, **kwargs):
        common.AbstractScanCommand.__init__(self, config, *args, **kwargs)
        config.add_option("SORT-BY", short_option = 's', type = "choice",
                          choices = ["atom", "refcount", "offset"], default = "offset",
                          help = "Sort by [offset | atom | refcount]", action = "store")

    def render_text(self, outfd, data):

        self.table_header(outfd,
                         [(self.offset_column(), "[addr]"),
                          ("AtomOfs(V)", "[addrpad]"),
                          ("Atom", "[addr]"),
                          ("Refs", "6"),
                          ("Pinned", "6"),
                          ("Name", ""),
                         ])

        for atom_table in data:

            # This defeats the purpose of having a generator, but
            # its required if we want to be able to sort. We also
            # filter string atoms here. 
            atoms = [a for a in atom_table.atoms() if a.is_string_atom()]

            if self._config.SORT_BY == "atom":
                attr = "Atom"
            elif self._config.SORT_BY == "refcount":
                attr = "ReferenceCount"
            else:
                attr = "obj_offset"

            for atom in sorted(atoms, key = lambda x: getattr(x, attr)):

                self.table_row(outfd,
                    atom_table.obj_offset,
                    atom.obj_offset,
                    atom.Atom, atom.ReferenceCount,
                    atom.Pinned,
                    str(atom.Name or "")
                    )

class Atoms(common.AbstractWindowsCommand):
    """Print session and window station atom tables"""

    def calculate(self):
        seen = []

        # Find the atom tables that belong to each window station 
        for wndsta in windowstations.WndScan(self._config).calculate():

            offset = wndsta.obj_native_vm.vtop(wndsta.pGlobalAtomTable)
            if offset in seen:
                continue
            seen.append(offset)

            # The atom table is dereferenced in the proper 
            # session space 
            atom_table = wndsta.AtomTable

            if atom_table.is_valid():
                yield atom_table, wndsta

        # Find atom tables not linked to specific window stations. 
        # This finds win32k!UserAtomHandleTable. 
        for table in AtomScan(self._config).calculate():
            if table.PhysicalAddress not in seen:
                yield table, obj.NoneObject("No windowstation")

    def render_text(self, outfd, data):

        self.table_header(outfd,
                         [("Offset(V)", "[addr]"),
                          ("Session", "^10"),
                          ("WindowStation", "^18"),
                          ("Atom", "[addr]"),
                          ("RefCount", "^10"),
                          ("HIndex", "^10"),
                          ("Pinned", "^10"),
                          ("Name", ""),
                         ])

        for atom_table, window_station in data:
            for atom in atom_table.atoms():
            
                ## Filter string atoms 
                if not atom.is_string_atom():
                    continue 
            
                self.table_row(outfd,
                    atom_table.PhysicalAddress,
                    window_station.dwSessionId,
                    window_station.Name,
                    atom.Atom,
                    atom.ReferenceCount,
                    atom.HandleIndex,
                    atom.Pinned,
                    str(atom.Name or "")
                    )
