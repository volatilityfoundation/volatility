# Volatility EditBox plugin
#
# Author: Bridgey the Geek <bridgeythegeek@gmail.com>
#
# This plugin is free software; you can redistribute it and/or modify
# it under the terms of GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PRACTICAL PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this plugin. If not, see <http://www.gnu.org/licenses/>.
#
# This work heavily inspired by  GDI Utilities from Dr Brendan Dolan-Gavitt PhD.
# <http://www.cc.gatech.edu/~brendan/volatility/>
#
# The iteration of the Windows objects is borrowed from the Windows plugin.
# <https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/gui/windows.py>
#
# This plugin wouldn't exist without the assistance of those on the volusers
# mailing list <http://lists.volatilesystems.com/mailman/listinfo/vol-users>.

"""
@author     : Bridgey the Geek
@license    : GPL 2 or later
@contact    : bridgeythegeek@gmail.com
"""

import os
import struct
import hashlib

import volatility
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.plugins.gui.messagehooks as messagehooks
import volatility.utils as utils
import volatility.win32 as win32

# Add a structure to the x86 GDI types.
gdi_types_x86 = {
    '_EDIT_x86': [ 0xF6, {
        'hBuf': [ 0x00, ['pointer', ['pointer', ['unsigned long']]]],
        'hWnd': [ 0x38, ['unsigned long']],
        'parenthWnd': [ 0x58, ['unsigned long']],
        'nChars': [0x0C, ['unsigned long']],
        'selStart': [0x14, ['unsigned long']],
        'selEnd': [0x18, ['unsigned long']],
        'pwdChar': [0x30, ['unsigned short']],
        'bEncKeyXP': [0xEC, ['unsigned char']], # XP
        'bEncKey': [0xF4, ['unsigned char']] # Win7/2008R2
        # TODO: bEncKey is hacky. Should have diff types for each.
    }],
    '_LISTBOX_x86': [ 0x40, {
        'hWnd': [0x00, ['unsigned long']],
        'parenthWnd': [0x04, ['unsigned long']],
        'atomHandle': [0x08, ['unsigned long']],
        'firstVisibleRow': [0x10, ['unsigned long']],
        'caretPos': [0x14, ['long']],
        'rowsVisible': [0x1C, ['unsigned long']],
        'itemCount': [0x20, ['unsigned long']],
        'stringsStart': [0x2C, ['unsigned long']],
        'stringsLength': [0x34, ['unsigned long']]
    }],
    '_COMBOBOX_x86': [0x28, {
        'hWnd': [0x00, ['unsigned long']],
        'parenthWnd': [0x04, ['unsigned long']],
        # 'atomHandle': [0x08, ['unsigned long']],
        # 'edithWnd': [0x4C, ['unsigned long']],
        'combolboxhWnd': [0x50, ['unsigned long']]
    }]
}

# Add a structure to the x64 GDI types.
gdi_types_x64 = {
    '_EDIT_x64': [ 0x142, {
        'hBuf': [0x00, ['pointer', ['pointer', ['unsigned long']]]],
        'hWnd': [0x40, ['unsigned long']],
        'parenthWnd': [0x60, ['unsigned long']],
        'nChars': [0x10, ['unsigned long']],
        'selStart': [0x18, ['unsigned long']],
        'selEnd': [0x20, ['unsigned long']],
        'pwdChar': [0x34, ['unsigned short']],
        'bEncKey': [0x140, ['unsigned char']]
    } ],
    '_LISTBOX_x64': [ 0x100, {
        'hWnd': [0x00, ['unsigned long']],
        'parenthWnd': [0x08, ['unsigned long']],
        'firstVisibleRow': [0x20, ['unsigned long']],
        'caretPos': [0x28, ['unsigned long']],
        'rowsVisible': [0x2C, ['unsigned long']],
        'itemCount': [0x30, ['unsigned long']],
        'stringsStart': [0x40, ['unsigned long']],
        'stringsLength': [0x4C, ['unsigned long']]
    } ],
    '_COMBOBOX_x64': [0x68, {
        'hWnd': [0x00, ['unsigned long']],
        'parenthWnd': [0x08, ['unsigned long']],
        'combolboxhWnd': [0x60, ['unsigned long']]
    }]
}

# Define the _EDIT_BOX_x86 structure.
class _EDIT_x86(obj.CType):

    def get_hBuf(self):
        # Double dereference
        ptr = (struct.unpack('<l', self.obj_vm.read(self.hBuf.obj_offset, 4)))[0]
        if not self.obj_vm.is_valid_address(ptr): return None
        ptr = (struct.unpack('<l', self.obj_vm.read(ptr, 4)))[0]
        if not self.obj_vm.is_valid_address(ptr): return None
        return ptr

    def get_text(self):
        key = self.bEncKeyXP if True else self.bEncKey
        s = self.obj_vm.read(self.get_hBuf(), self.nChars * 2)
        if not self.pwdChar == 0x00:
            s = EditBox.RtlRunDecodeUnicodeString(key, s)
        return '' if not s else s

# Define the _EDIT_BOX_x64 structure.
class _EDIT_x64(obj.CType):

    def get_hBuf(self):
        # Double dereference
        ptr = (struct.unpack('<l', self.obj_vm.read(self.hBuf.obj_offset, 4)))[0]
        if not self.obj_vm.is_valid_address(ptr): return None
        ptr = (struct.unpack('<l', self.obj_vm.read(ptr, 4)))[0]
        if not self.obj_vm.is_valid_address(ptr): return None
        return ptr

    def get_text(self):
        s = self.obj_vm.read(self.get_hBuf(), self.nChars * 2)
        if not self.pwdChar == 0x00:
            s = EditBox.RtlRunDecodeUnicodeString(self.bEncKey, s)
        return '' if not s else s

# Define the _LISTBOX_x86 structure.
class _LISTBOX_x86(obj.CType):

    def get_text(self):
        string_array = self.obj_vm.read(self.stringsStart, self.stringsLength).split(b'\x00\x00')[:-1]
        return ', '.join(string_array) if string_array else ''

# Define the _LISTBOX_x64 structure.
class _LISTBOX_x64(obj.CType):

    def get_text(self):
        string_array = self.obj_vm.read(self.stringsStart, self.stringsLength).split(b'\x00\x00')[:-1]
        return ', '.join(string_array) if string_array else ''

# Define the _COMBOBOX_x86 structure.
class _COMBOBOX_x86(obj.CType):
    pass

# Define the _COMBOBOX_x64 structure.
class _COMBOBOX_x64(obj.CType):
    pass

class EditBoxVTypes(obj.ProfileModification):
    """This modification adds the gdi_types_x(86|64)."""

    def check(self, profile):
        m = profile.metadata
        return m.get('os', None) == 'windows'

    def modification(self, profile):
        profile.vtypes.update(gdi_types_x86)
        profile.vtypes.update(gdi_types_x64)

class EditBoxObjectClasses(obj.ProfileModification):
    """Add the new class definitions."""

    def modification(self, profile):
        profile.object_classes.update({
            '_EDIT_x86': _EDIT_x86,
            '_EDIT_x64': _EDIT_x64,
            '_LISTBOX_x86': _LISTBOX_x86,
            '_LISTBOX_x64': _LISTBOX_x64,
            '_COMBOBOX_x86': _COMBOBOX_x86,
            '_COMBOBOX_x64': _COMBOBOX_x64
        })

class EditBox(messagehooks.MessageHooks):
    """Dumps various data from ComCtl Edit controls (experimental: ListBox, ComboBox)"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        # Plugin parameters
        self._config.add_option('DUMP-DIR', short_option='D', default=None,
                                help='Directory to which to dump found text',
                                action='store', type='str')
        self._config.add_option('NULLS', short_option='n', default=False,
                                help='keep nulls when outputting to stdout', action='store_true')
        self._config.add_option('PID', short_option='p', default=None,
                                help='This Process ID', action='store', type='int')
        self._config.add_option('MINIMAL', short_option='m', default=None,
                                help='Process name and text only',
                                action='store_true')
        self._config.add_option('EXPERIMENTAL', short_option='e', default=None,
                                help='Enable experimental options',
                                action='store_true')
        self._config.add_option('EXPERIMENTAL-ONLY', short_option='E', default=None,
                                help='Only do experimental options',
                                action='store_true')
        # Object variables
        self._addr_space = utils.load_as(self._config)
        self._profile_is_32bit = (self._addr_space.profile.metadata['memory_model'] == '32bit')
        self._tagWND_size = self._addr_space.profile.get_obj_size('tagWND')

    @staticmethod
    def is_valid_profile(profile):
        """Returns True if the plugin is valid for the current profile"""

        return profile.metadata.get('os', 'unknown') == 'windows'

    @staticmethod
    def RtlRunDecodeUnicodeString(key, data):
        s = ''.join([chr(ord(data[i-1]) ^ ord(data[i]) ^ key) for i in range(1,len(data))])
        s = chr(ord(data[0]) ^ (key | 0x43)) + s
        return s

    def dump_edit(self, dump_to_file, rm_nulls, atom_class_name, context, outfd, wnd, task):
        """Process an Edit"""

        task_space = task.get_process_address_space()

        addr_wndextra = wnd.v() + self._tagWND_size
        val = wnd.obj_vm.read(addr_wndextra, wnd.cbwndExtra)

        # Build an _EDIT_BOX_x?? object from the WndExtra bytes
        if self._profile_is_32bit or task.IsWow64:
            edit_box_type = '_EDIT_x86'
            wndextra = struct.unpack('<I', val)[0]
        else:
            edit_box_type = '_EDIT_x64'
            wndextra = struct.unpack('<Q', val)[0]
        
        editbox = obj.Object(edit_box_type, offset=wndextra, vm=task_space)
        valid_hbuf = not (editbox.get_hBuf() is None)

        # wndextra was 0 or some other invalid address
        if editbox is None:
            return

        isPassword = not (editbox.pwdChar == 0x00)
        
        if valid_hbuf:
            # Get the text from the control
            the_text = editbox.get_text()
            # Calc the MD5
            md5 = hashlib.md5(the_text).hexdigest()

        # Dump the info
        if self._config.minimal:
            outfd.write('{0}:{1}\n'.format(wnd.Process.UniqueProcessId, wnd.Process.ImageFileName))
        else:
            outfd.write('{0}\n'.format('*' * 55))

            if not valid_hbuf:
                outfd.write('{0} invalid hBuf - can\'t get text {0}\n'.format('*' * 12))
                outfd.write('{0}\n'.format('*' * 55))

            outfd.write('Wnd context          : {0}\n'.format(context))
            outfd.write('pointer-to tagWND    : {0:#x} [{1:#x}]\n'.format(
                wnd.obj_offset, task_space.vtop(wnd.obj_offset)))
            outfd.write('pid                  : {0}\n'.format(wnd.Process.UniqueProcessId))
            outfd.write('imageFileName        : {0}\n'.format(wnd.Process.ImageFileName))

            if not self._profile_is_32bit:
                outfd.write('wow64                : {0}\n'.format('Yes' if task.IsWow64 else 'No'))

            outfd.write('atom_class           : {0}\n'.format(atom_class_name))
            outfd.write('address-of cbwndExtra: {0:#x} [{1:#x}]\n'.format(
                wnd.cbwndExtra.obj_offset, task_space.vtop(wnd.cbwndExtra.obj_offset)))
            outfd.write('value-of cbwndExtra  : {0} ({0:#x})\n'.format(wnd.cbwndExtra))
            outfd.write('address-of WndExtra  : {0:#x} [{1:#x}]\n'.format(
                addr_wndextra, task_space.vtop(addr_wndextra)))
            outfd.write('value-of WndExtra    : {0:#x} [{1:#x}]\n'.format(wndextra, task_space.vtop(wndextra)))

            if valid_hbuf:
                outfd.write('pointer-to hBuf      : {0:#x} [{1:#x}]\n'.format(
                    editbox.get_hBuf(), task_space.vtop(editbox.get_hBuf())))
            else:
                outfd.write('pointer-to hBuf      : -invalid-\n')

            outfd.write('hWnd                 : {0:#x}\n'.format(editbox.hWnd))
            outfd.write('parenthWnd           : {0:#x}\n'.format(editbox.parenthWnd))
            outfd.write('nChars               : {0} ({0:#x})\n'.format(editbox.nChars))
            outfd.write('selStart             : {0} ({0:#x})\n'.format(editbox.selStart))
            outfd.write('selEnd               : {0} ({0:#x})\n'.format(editbox.selEnd))

            if valid_hbuf:
                outfd.write('text_md5             : {0}\n'.format(md5))
        
            outfd.write('isPwdControl         : {0}\n'.format('Yes' if isPassword else 'No'))
            if isPassword:
                outfd.write('pwdChar              : {0:#x}\n'.format(editbox.pwdChar))
        
        if valid_hbuf:
            if dump_to_file:  # Write to file, named as per the MD5
                with open(os.path.join(self._config.dump_dir, md5 + '.txt'), 'wb') as f:
                    f.write(the_text)
            else:  # Write to the screen
                if rm_nulls:
                    the_text = the_text.replace('\x00', '')
                outfd.write('{0}\n'.format(the_text))

    def dump_listbox(self, dump_to_file, atom_class_name, context, outfd, wnd, task):
        """Process a ListBox"""
        task_space = task.get_process_address_space()

        addr_wndextra = wnd.v() + self._tagWND_size
        val = wnd.obj_vm.read(addr_wndextra, wnd.cbwndExtra)

        # Build a _LISTBOX_x?? object from the WndExtra bytes
        if self._profile_is_32bit:
            listbox_type = '_LISTBOX_x86'
            wndextra = struct.unpack('<I', val)[0]
        elif task.IsWow64:
            listbox_type = '_LISTBOX_x86'
            wndextra = struct.unpack('<I', val)[0]
        else:
            listbox_type = '_LISTBOX_x64'
            wndextra = struct.unpack('<Q', val)[0]
        listbox = obj.Object(listbox_type, offset=wndextra, vm=task_space)

        outfd.write('{0}\n'.format('*' * 55))
        outfd.write('*** Experimental {0}\n'.format('*' * 38))
        outfd.write('{0}\n'.format('*' * 55))
        outfd.write('Wnd context          : {0}\n'.format(context))
        outfd.write('pointer-to tagWND    : {0:#x} [{1:#x}]\n'.format(wnd.obj_offset, task_space.vtop(wnd.obj_offset)))
        outfd.write('pid                  : {0}\n'.format(wnd.Process.UniqueProcessId))
        outfd.write('process              : {0}\n'.format(wnd.Process.ImageFileName))
        if not self._profile_is_32bit:
            outfd.write('wow64                : {0}\n'.format('Yes' if task.IsWow64 else 'No'))
        outfd.write('atom_class           : {0}\n'.format(atom_class_name))
        outfd.write('address-of cbwndExtra: {0:#x} [{1:#x}]\n'.format(
            wnd.cbwndExtra.obj_offset, task_space.vtop(wnd.cbwndExtra.obj_offset)))
        outfd.write('value-of cbwndExtra  : {0} ({0:#x})\n'.format(wnd.cbwndExtra))
        outfd.write('address-of WndExtra  : {0:#x} [{1:#x}]\n'.format(addr_wndextra, task_space.vtop(addr_wndextra)))
        outfd.write('value-of WndExtra    : {0:#x} [{1:#x}]\n'.format(wndextra, task_space.vtop(wndextra)))
        outfd.write('firstVisibleRow      : {0} ({0:#x})\n'.format(listbox.firstVisibleRow))
        outfd.write('caretPos             : {0} ({0:#x})\n'.format(listbox.caretPos))
        outfd.write('rowsVisible          : {0} ({0:#x})\n'.format(listbox.rowsVisible))
        outfd.write('itemCount            : {0} ({0:#x})\n'.format(listbox.itemCount))
        outfd.write('stringsStart         : {0:#x} [{1:#x}]\n'.format(
            listbox.stringsStart, task_space.vtop(listbox.stringsStart)))
        outfd.write('stringsLength        : {0} ({0:#x})\n'.format(listbox.stringsLength))
        outfd.write('strings              : {0}\n'.format(listbox.get_text()))

    def dump_combobox(self, dump_to_file, atom_class_name, context, outfd, wnd, task):
        """Process a ComboBox"""
        task_space = task.get_process_address_space()

        addr_wndextra = wnd.v() + self._tagWND_size
        val = wnd.obj_vm.read(addr_wndextra, wnd.cbwndExtra)

        # Build a _COMBOBOX_x?? object from the WndExtra bytes
        if self._profile_is_32bit:
            combobox_type = '_COMBOBOX_x86'
            wndextra = struct.unpack('<I', val)[0]
        elif task.IsWow64:
            combobox_type = '_COMBOBOX_x86'
            wndextra = struct.unpack('<I', val)[0]
        else:
            combobox_type = '_COMBOBOX_x64'
            wndextra = struct.unpack('<Q', val)[0]
        combobox = obj.Object(combobox_type, offset = wndextra, vm = task_space)
        
        outfd.write('{0}\n'.format('*' * 55))
        outfd.write('*** Experimental {0}\n'.format('*' * 38))
        outfd.write('{0}\n'.format('*' * 55))
        outfd.write('Wnd context          : {0}\n'.format(context))
        outfd.write('pointer-to tagWND    : {0:#x} [{1:#x}]\n'.format(wnd.obj_offset, task_space.vtop(wnd.obj_offset)))
        outfd.write('pid                  : {0}\n'.format(wnd.Process.UniqueProcessId))
        outfd.write('process              : {0}\n'.format(wnd.Process.ImageFileName))
        if not self._profile_is_32bit:
            outfd.write('wow64                : {0}\n'.format('Yes' if task.IsWow64 else 'No'))
        outfd.write('atom_class           : {0}\n'.format(atom_class_name))
        outfd.write('address-of cbwndExtra: {0:#x} [{1:#x}]\n'.format(
            wnd.cbwndExtra.obj_offset, task_space.vtop(wnd.cbwndExtra.obj_offset)))
        outfd.write('value-of cbwndExtra  : {0} ({0:#x})\n'.format(wnd.cbwndExtra))
        outfd.write('address-of WndExtra  : {0:#x} [{1:#x}]\n'.format(addr_wndextra, task_space.vtop(addr_wndextra)))
        outfd.write('value-of WndExtra    : {0:#x} [{1:#x}]\n'.format(wndextra, task_space.vtop(wndextra)))
        # if combobox.hWnd != combobox.edithWnd:
        #     outfd.write('handle-of edit       : {0:#x}\n'.format(combobox.edithWnd))
        outfd.write('handle-of combolbox  : {0:#x}\n'.format(combobox.combolboxhWnd))

    def render_text(self, outfd, data):
        """Output the data"""

        # Are we dumping the text to files?
        dump_to_file = self._config.dump_dir != None
        if dump_to_file and not os.path.isdir(self._config.dump_dir):
            debug.error('{0} is not a directory'.format(self._config.dump_dir))

        # Are we removing nulls?
        rm_nulls = not self._config.nulls

        tasks = win32.tasks.pslist(self._addr_space)

        # Build a dict of the tasks, indexed by pid
        the_tasks = {}
        if self._config.pid is None:
            for t in tasks:
                the_tasks[int(t.UniqueProcessId)] = t
        else:
            for t in tasks:
                if self._config.pid == t.UniqueProcessId:
                    the_tasks[int(t.UniqueProcessId)] = t
                    break
        outfd.write('{0} process{1} to check.\n'.format(len(the_tasks), '' if len(the_tasks) == 1 else 'es'))

        # In case the PID's not found
        if len(the_tasks) < 1:
            return

        counts = {}
        for winsta, atom_tables in data:
            for desktop in winsta.desktops():
                for wnd, _level in desktop.windows(desktop.DeskInfo.spwnd):

                    if self._config.pid is None or int(wnd.Process.UniqueProcessId) in the_tasks:

                        atom_class = self.translate_atom(winsta, atom_tables, wnd.ClassAtom)

                        if not isinstance(atom_class, volatility.obj.NoneObject) and \
                            not isinstance(wnd.Process.ImageFileName, volatility.obj.NoneObject):

                            atom_class_name = str(atom_class)
                            context = '{0}\\{1}\\{2}'.format(winsta.dwSessionId, winsta.Name, desktop.Name)

                            if not self._config.experimental_only:

                                # Edit control
                                if atom_class_name.endswith('!Edit'):  # or atom_class_name == 'Edit':
                                    task = the_tasks[int(wnd.Process.UniqueProcessId)]
                                    self.dump_edit(dump_to_file, rm_nulls, atom_class_name, context, outfd, wnd, task)
                                    if 'Edit' in counts:
                                        counts['Edit'] += 1
                                    else:
                                        counts['Edit'] = 1

                            # Experimental options
                            if self._config.experimental or self._config.experimental_only:
                            
                                # Listbox control
                                if atom_class_name.endswith('!Listbox'):  # or atom_class_name.endswith('!ComboLBox')):
                                    task = the_tasks[int(wnd.Process.UniqueProcessId)]
                                    self.dump_listbox(dump_to_file, atom_class_name, context, outfd, wnd, task)
                                    if 'ListBox' in counts:
                                        counts['ListBox'] += 1
                                    else:
                                        counts['ListBox'] = 1

                                # Combobox control
                                elif atom_class_name.endswith('!Combobox'):
                                    task = the_tasks[int(wnd.Process.UniqueProcessId)]
                                    self.dump_combobox(dump_to_file, atom_class_name, context, outfd, wnd, task)
                                    if 'ComboBox' in counts:
                                        counts['ComboBox'] += 1
                                    else:
                                        counts['ComboBox'] = 1
        
        outfd.write('{0}\n'.format('*' * 55))
        for k in counts.keys():
            outfd.write('{0} {1} {2} found.\n'.format(counts[k], k, 'control' if counts[k] == 1 else 'controls'))
