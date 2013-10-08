# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
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
import volatility.utils as utils
import volatility.plugins.gui.atoms as atoms
import volatility.plugins.gui.constants as consts
import volatility.plugins.gui.sessions as sessions

# Offsets to (_catomSysTableEntries, _aatomSysLoaded) in win32k.sys. We use
# this for translating the ihmod value into a fully-qualified DLL path name 
# used by messagehooks and eventhooks plugins. If the values for your system
# aren't in the list, the plugins will still work, but the names of the Hook
# Module will not be available.
message_offsets_x86 = [
      (0x001ab0a0, 0x001ab060), # ? (shylock.dmp)
      (0x001aaea0, 0x001aae60), # 5.1.2600.6033 (XP SP3)
      (0x001ac640, 0x001ac600), # 5.1.2600.6149 (XP)
      (0x001a9400, 0x001a93c0), # 5.1.2600.5512 (XP SP3)
      (0x001a9220, 0x001a91e0), # 5.1.2600.3335 (XP SP2) 
      (0x001a6f00, 0x001a6ec0), # 5.1.2600.2180 (XP SP2)    
      (0x001a0338, 0x001a03c0), # ? (W2K3 SP0)
      (0x001b5600, 0x001b55c0), # 5.2.3790.4980 (W2K3 SP2)
      (0x001b1440, 0x001b1400), # 5.2.3790.1830 (W2K3 SP1)
      (0x001de0e0, 0x001de0a0), # 6.0.6000.16386 (Vista SP0)
      (0x001e01e0, 0x001e01a0), # 6.0.6002.18005 (Vista SP2)
      (0x001df0e0, 0x001df0a0), # 6.0.6001.18000 (W2K8 SP1)
      (0x00219800, 0x002197C0), # 6.1.7600.16385 (Win 7 SP0)
      (0x0021e800, 0x0021e7c0), # 6.1.7600.16988 (Win 7 SP0)
      (0x0021a900, 0x0021a8c0), # 6.1.7601.17514 (Win 7 SP1)
      ]
message_offsets_x64 = [
      (0x003b3880, 0x003b3840), # 5.2.3790.1830 (W2K3 SP1 / XP SP1)
      (0x003b4880, 0x003b4840), # 5.2.3790.3959 (W2K3 SP2 / XP SP2)
      (0x0028ba20, 0x0028b9e0), # 6.0.6000.16386 (Vista SP0)
      (0x00288a20, 0x002889e0), # 6.0.6001.18000 (Vista SP1 / W2K8 SP1)
      (0x00289c20, 0x00289be0), # 6.0.6002.18005 (Vista SP2 / W2K8 SP2)
      (0x002da480, 0x002da440), # 6.1.7600.16385 (Win 7 SP0)
      (0x002db6a0, 0x002db660), # 6.1.7601.17514 (Win 7 SP1)
      (0x002e08a0, 0x002e0860), # 6.1.7601.17842 (W2K8 R2 SP1)
      (0x002e06a0, 0x002e0660), # ?? (W2K8 R2 SP1)
      ]

class MessageHooks(atoms.Atoms, sessions.SessionsMixin):
    """List desktop and thread window message hooks"""

    def calculate(self):
        # Get all the atom tables and window stations 
        atom_tables = dict((atom_table, winsta)
            for (atom_table, winsta)
            in atoms.Atoms(self._config).calculate())

        # Unique window stations
        window_stations = [
                winsta for winsta in atom_tables.values()
                if winsta]

        for winsta in window_stations:
            yield winsta, atom_tables

    def translate_atom(self, winsta, atom_tables, atom_id):
        """
        Translate an atom into an atom name.

        @param winsta: a tagWINDOWSTATION in the proper 
        session space 

        @param atom_tables: a dictionary with _RTL_ATOM_TABLE
        instances as the keys and owning window stations as
        the values. 

        @param index: the index into the atom handle table. 
        """

        # First check the default atoms
        if consts.DEFAULT_ATOMS.has_key(atom_id):
            return consts.DEFAULT_ATOMS[atom_id].Name

        # A list of tables to search. The session atom tables
        # have priority and will be searched first. 
        table_list = [
                table for (table, window_station)
                in atom_tables.items() if window_station == None
                ]
        table_list.append(winsta.AtomTable)

        ## Fixme: the session atom tables are found via physical
        ## AS pool tag scanning, and there's no good way (afaik)
        ## to associate the table with its session. Thus if more
        ## than one session has atoms with the same id but different
        ## values, then we could possibly select the wrong one. 
        for table in table_list:
            atom = table.find_atom(atom_id)
            if atom:
                return atom.Name

        return obj.NoneObject("Cannot translate atom {0:#x}".format(atom_id))

    def translate_hmod(self, winsta, atom_tables, index):
        """
        Translate an ihmod (index into a handle table) into
        an atom. This requires locating the win32k!_aatomSysLoaded 
        symbol. If the  symbol cannot be found, we'll just report 
        back the ihmod value. 

        @param winsta: a tagWINDOWSTATION in the proper 
        session space 

        @param atom_tables: a dictionary with _RTL_ATOM_TABLE
        instances as the keys and owning window stations as
        the values. 

        @param index: the index into the atom handle table. 
        """

        # No need to translate these
        if index == -1:
            return "(Current Module)"

        # To get an _MM_SESSION_SPACE we first start with a 
        # kernel AS and walk processes. 
        kernel_space = utils.load_as(self._config)

        session = self.find_session_space(
                kernel_space, winsta.dwSessionId)

        # Report back the ihmod value if we fail 
        if not session:
            return hex(index)

        if winsta.obj_vm.profile.metadata.get('memory_model', '32bit') == '32bit':
            message_offsets = message_offsets_x86
        else:
            message_offsets = message_offsets_x64

        # Iterate over the possible offsets for win32k globals 
        for (count_offset, table_offset) in message_offsets:

            # This is _catomSysTableEntries
            count = obj.Object("unsigned long",
                            offset = session.Win32KBase + count_offset,
                            vm = session.obj_vm)

            # We fail for this offset if the count is unreadable, 
            # its greater than 32, or its less than the requested
            # handle table index. 
            if (count == None or count == 0 or count > 32 or
                    count <= index):
                continue

            # An array of atom IDs
            atomlist = obj.Object("Array", targetType = "unsigned short",
                offset = session.Win32KBase + table_offset,
                count = count, vm = session.obj_vm)

            # Our last sanity check is that the number of valid 
            # atoms equals the claimed number of atoms. This check 
            # is currently commented out because on at least one image
            # (shylock.dmp), the count is 3 but there are only 2 valid
            # atoms, thus we end up skipping it. 
            #valid_entries = len([atom for atom in atoms if atom != 0])
            #if count != valid_entries:
            #    continue

            # We can stop after finding a potential atom 
            atom_id = atomlist[index]

            # Attempt to translate the atom into a module name
            module = self.translate_atom(winsta, atom_tables, atom_id)
            if module:
                return module

        # Report back the ihmod value if we fail 
        return hex(index)

    def render_text(self, outfd, data):
        """Render output in table form"""

        self.table_header(outfd,
                        [("Offset(V)", "[addrpad]"),
                         ("Sess", "<6"),
                         ("Desktop", "20"),
                         ("Thread", "30"),
                         ("Filter", "20"),
                         ("Flags", "20"),
                         ("Function", "[addrpad]"),
                         ("Module", ""),
                        ])

        for winsta, atom_tables in data:
            for desk in winsta.desktops():
                for name, hook in desk.hooks():
                    module = self.translate_hmod(winsta, atom_tables, hook.ihmod)
                    self.table_row(outfd,
                            hook.obj_offset,
                            winsta.dwSessionId,
                            "{0}\\{1}".format(winsta.Name, desk.Name),
                            "<any>", name,
                            str(hook.flags),
                            hook.offPfn,
                            module,
                            )

                for thrd in desk.threads():
                    info = "{0} ({1} {2})".format(
                            thrd.pEThread.Cid.UniqueThread,
                            thrd.ppi.Process.ImageFileName,
                            thrd.ppi.Process.UniqueProcessId
                            )
                    for name, hook in thrd.hooks():
                        module = self.translate_hmod(winsta, atom_tables, hook.ihmod)
                        self.table_row(outfd,
                                    hook.obj_offset,
                                    winsta.dwSessionId,
                                    "{0}\\{1}".format(winsta.Name, desk.Name),
                                    info, name,
                                    str(hook.flags),
                                    hook.offPfn,
                                    module,
                                    )

    def render_block(self, outfd, data):
        """Render output as a block"""

        def write_block(outfd, winsta, desk, hook, module, thread):
            outfd.write("{0:<10} : {1:#x}\n".format("Offset(V)", hook.obj_offset))
            outfd.write("{0:<10} : {1}\n".format("Session", winsta.dwSessionId))
            outfd.write("{0:<10} : {1}\n".format("Desktop", "{0}\\{1}".format(winsta.Name, desk.Name)))
            outfd.write("{0:<10} : {1}\n".format("Thread", thread))
            outfd.write("{0:<10} : {1}\n".format("Filter", name))
            outfd.write("{0:<10} : {1}\n".format("Flags", str(hook.flags)))
            outfd.write("{0:<10} : {1:#x}\n".format("Procedure", hook.offPfn))
            outfd.write("{0:<10} : {1}\n".format("ihmod", hook.ihmod))
            outfd.write("{0:<10} : {1}\n\n".format("Module", module))

        for winsta, atom_tables in data:
            for desk in winsta.desktops():
                for name, hook in desk.hooks():
                    module = self.translate_hmod(winsta, atom_tables, hook.ihmod)
                    write_block(outfd, winsta, desk, hook, module, "<any>")

                for thrd in desk.threads():
                    info = "{0} ({1} {2})".format(
                            thrd.pEThread.Cid.UniqueThread,
                            thrd.ppi.Process.ImageFileName,
                            thrd.ppi.Process.UniqueProcessId
                            )
                    for name, hook in thrd.hooks():
                        module = self.translate_hmod(winsta, atom_tables, hook.ihmod)
                        write_block(outfd, winsta, desk, hook, module, info)
