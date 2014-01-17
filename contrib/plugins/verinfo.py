# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import re
import sre_constants
import struct
import volatility.plugins.procdump as procdump
import volatility.win32 as win32
import volatility.obj as obj
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.exceptions as exceptions

MAX_STRING_BYTES = 260

ver_types = {
'_IMAGE_RESOURCE_DIRECTORY' : [ 0x12, {
  'Characteristics' : [ 0x0, ['unsigned long']],
  'Timestamp' : [ 0x4, ['unsigned long']],
  'MajorVersion': [ 0x8, ['unsigned short']],
  'Minorversion': [ 0xa, ['unsigned short']],
  'NamedEntriesCount': [ 0xc, ['unsigned short']],
  'IdEntriesCount': [0xe, ['unsigned short']],
  'Entries': [0x10, ['array', lambda x: x.NamedEntriesCount + x.IdEntriesCount, ['_IMAGE_RESOURCE_DIRECTORY_ENTRY']]],
} ],
'_IMAGE_RESOURCE_DIRECTORY_ENTRY': [0x8, {
  'Name' : [ 0x0, ['unsigned long']],
  'DataOffset' : [ 0x4, ['unsigned long']],
} ],
'_IMAGE_RESOURCE_DATA_ENTRY' : [0x10, {
  'DataOffset' : [0x0, ['unsigned long']],
  'Size' : [0x4, ['unsigned long']],
  'CodePage' : [0x8, ['unsigned long']],
  'Reserved' : [0xc, ['unsigned long']],
} ],
'_IMAGE_RESOURCE_DIR_STRING_U' : [0x4, {
  'Length': [0x0, ['unsigned short']],
  'Value' : [0x2, ['array', lambda x: x.Length, ['unsigned short']]],
} ],
'_VS_VERSION_INFO' : [0x26, {
  'Length': [0x0, ['unsigned short']],
  'ValueLength': [0x2, ['unsigned short']],
  'Type': [0x4, ['unsigned short']],
  'Key': [0x6, ['array', len("VS_VERSION_INFO "), ['unsigned short']]],
  'FileInfo': [lambda x: (((x.Key.obj_offset + x.Key.size() + 3) / 4) * 4), ['_VS_FIXEDFILEINFO']],
} ],
'VerStruct' : [0x26, {
  'Length': [0x0, ['unsigned short']],
  'ValueLength': [0x2, ['unsigned short']],
  'Type': [0x4, ['unsigned short']],
  'Key': [0x6, ['array', MAX_STRING_BYTES, ['unsigned short']]],
} ],
'_VS_FIXEDFILEINFO': [0x34, {
  'Signature': [0x0, ['unsigned long']],
  'StructVer': [0x4, ['unsigned long']],
  'FileVerMS': [0x8, ['unsigned long']],
  'FileVerLS': [0xC, ['unsigned long']],
  'ProdVerMS': [0x10, ['unsigned long']],
  'ProdVerLS': [0x14, ['unsigned long']],
  'FileFlagsMask': [0x18, ['unsigned long']],
  'FileFlags': [0x1C, ['unsigned long']],
  'FileOS': [0x20, ['Enumeration', {'choices': {
    0x0: 'Unknown',
    0x10000: 'DOS',
    0x20000: 'OS/2 16-bit',
    0x30000: 'OS/2 32-bit',
    0x40000: 'Windows NT',
    0x1: 'Windows 16-bit',
    0x2: 'Presentation Manager 16-bit',
    0x3: 'Presentation Manager 32-bit',
    0x4: 'Windows 32-bit',
    0x10001: 'Windows 16-bit running on DOS',
    0x10004: 'Windows 32-bit running on DOS',
    0x20002: 'Presentation Manager running on OS/2 (16-bit)',
    0x30003: 'Presentation Manager running on OS/2 (32-bit)',
    0x40004: 'Windows NT',
                                                  }} ]],
  'FileType': [0x24, ['Enumeration', {'choices': {
    0x0: 'Unknown',
    0x1: 'Application',
    0x2: 'Dynamic Link Library',
    0x3: 'Driver',
    0x4: 'Font',
    0x5: 'Virtual Device',
    0x7: 'Static Library',
                                                  }} ]],
  'FileSubType': [0x28, ['unsigned long']],
  'FileDate': [0x2C, ['WinTimeStamp']],
} ],
}

class VerStruct(obj.CType):
    """Generic Version Structure"""

    def _determine_key(self, findend = False):
        """Determines the string value for or end location of the key"""
        if self.Key != None:
            name = None
            for n in self.Key:
                if n == None:
                    return n
                # If the letter's valid, then deal with it
                if n == 0:
                    if findend:
                        return n.obj_offset + n.size()
                    name = self.obj_vm.read(self.Key.obj_offset, n.obj_offset - self.Key.obj_offset).decode("utf16", "ignore").encode("ascii", 'backslashreplace')
                    break
            return name
        return self.Key

    def get_key(self):
        """Returns the VerStruct Name"""
        return self._determine_key()

    def offset_pad(self, offset):
        """Pads an offset to a 32-bit alignment"""
        return (((offset + 3) / 4) * 4)

    def get_children(self):
        """Returns the available children"""
        offset = self.offset_pad(self._determine_key(True))
        if self.ValueLength > 0:
            # Nasty hardcoding unicode (length*2) length in here, 
            # but what else can we do?
            return self.obj_vm.read(offset, self.ValueLength * 2)
        else:
            return self._recurse_children(offset)

    def _recurse_children(self, offset):
        """Recurses thorugh the available children"""
        while offset < self.obj_offset + self.Length:
            item = obj.Object("VerStruct", offset = offset, vm = self.obj_vm, parent = self)
            if item.Length < 1 or item.get_key() == None:
                raise StopIteration("Could not recover a key for a child at offset {0}".format(item.obj_offset))
            yield item.get_key(), item.get_children()
            offset = self.offset_pad(offset + item.Length)
        raise StopIteration("No children")

class _VS_VERSION_INFO(VerStruct):
    """Version Information"""

    def get_children(self):
        """Recurses through the children of a Version Info records"""
        offset = self.offset_pad(self.FileInfo.obj_offset + self.ValueLength)
        return self._recurse_children(offset)

class _VS_FIXEDFILEINFO(obj.CType):
    """Fixed (language and codepage independent) information"""

    def file_version(self):
        """Returns the file version"""
        return self.get_version(self.FileVerMS) + "." + self.get_version(self.FileVerLS)

    def product_version(self):
        """Returns the product version"""
        return self.get_version(self.ProdVerMS) + "." + self.get_version(self.ProdVerLS)

    def get_version(self, value):
        """Returns a version in four parts"""
        version = []
        for i in range(2):
            version = [(value >> (i * 16)) & 0xFFFF] + version
        return '.'.join([str(x) for x in version])

    def file_type(self):
        """Returns the type of the file"""
        ftype = str(self.FileType)
        choices = None
        if self.FileType == 'Driver':
            choices = {
                       0x0: 'Unknown',
                       0x1: 'Printer',
                       0x2: 'Keyboard',
                       0x3: 'Language',
                       0x4: 'Display',
                       0x5: 'Mouse',
                       0x6: 'Network',
                       0x7: 'System',
                       0x8: 'Installable',
                       0x9: 'Sound',
                       0xA: 'Comms',
                       0xB: 'Input Method',
                       0xC: 'Versioned Printer',
                       }
        elif self.FileType == 'Font':
            choices = {
                       0x1: 'Raster',
                       0x2: 'Vector',
                       0x3: 'Truetype',
                       }
        if choices != None:
            subtype = obj.Object('Enumeration', 0x28, vm = self.obj_vm, parent = self, choices = choices)
            ftype += " (" + str(subtype) + ")"

        return ftype

    def flags(self):
        """Returns the file's flags"""
        data = struct.pack('=I', self.FileFlags & self.FileFlagsMask)
        addr_space = addrspace.BufferAddressSpace(self.obj_vm.get_config(), 0, data)
        bitmap = {'Debug': 0,
                  'Prerelease': 1,
                  'Patched': 2,
                  'Private Build': 3,
                  'Info Inferred': 4,
                  'Special Build' : 5,
                 }
        return obj.Object('Flags', offset = 0, vm = addr_space, bitmap = bitmap)

    def v(self):
        """Returns the value of the structure"""
        val = ("File version    : {0}\n" +
               "Product version : {1}\n" +
               "Flags           : {2}\n" +
               "OS              : {3}\n" +
               "File Type       : {4}\n" +
               "File Date       : {5}").format(self.file_version(), self.product_version(),
                                                 self.flags(), self.FileOS, self.file_type(), self.FileDate or '')
        return val

class _IMAGE_RESOURCE_DIR_STRING_U(obj.CType):
    """Handles Unicode-esque strings in IMAGE_RESOURCE_DIRECTORY structures"""
    # This is very similar to a UNICODE object, perhaps they should be merged somehow?
    def v(self):
        """Value function for _IMAGE_RESOURCE_DIR_STRING_U"""
        try:
            length = self.Length.v()
            if length > 1024:
                length = 0
            data = self.obj_vm.read(self.Value.obj_offset, length)
            return data.decode("utf16", "ignore").encode("ascii", 'backslashreplace')
        except Exception, _e:
            return ''

class _IMAGE_RESOURCE_DIRECTORY(obj.CType):
    """Handles Directory Entries"""
    def __init__(self, theType = None, offset = None, vm = None, parent = None, *args, **kwargs):
        self.sectoffset = offset
        obj.CType.__init__(self, theType = theType, offset = offset, vm = vm, parent = parent, *args, **kwargs)

    def get_entries(self):
        """Gets a tree of the entries from the top level IRD"""
        for irde in self.Entries:
            if irde != None:
                if irde.Name & 0x80000000:
                    # Points to a Name object
                    name = obj.Object("_IMAGE_RESOURCE_DIR_STRING_U", (irde.Name & 0x7FFFFFFF) + self.sectoffset, vm = self.obj_vm, parent = irde)
                else:
                    name = int(irde.Name)
                if irde.DataOffset & 0x80000000:
                    # We're another DIRECTORY
                    retobj = obj.Object("_IMAGE_RESOURCE_DIRECTORY", (irde.DataOffset & 0x7FFFFFFF) + self.sectoffset, vm = self.obj_vm, parent = irde)
                    retobj.sectoffset = self.sectoffset
                else:
                    # We're a DATA_ENTRY
                    retobj = obj.Object("_IMAGE_RESOURCE_DATA_ENTRY", irde.DataOffset + self.sectoffset, vm = self.obj_vm, parent = irde)
                yield (name, bool(irde.DataOffset & 0x80000000), retobj)

resource_types = {
 'RT_CURSOR'       : 1,
 'RT_BITMAP'       : 2,
 'RT_ICON'         : 3,
 'RT_MENU'         : 4,
 'RT_DIALOG'       : 5,
 'RT_STRING'       : 6,
 'RT_FONTDIR'      : 7,
 'RT_FONT'         : 8,
 'RT_ACCELERATOR'  : 9,
 'RT_RCDATA'       : 10,
 'RT_MESSAGETABLE' : 11,
 'RT_GROUP_CURSOR' : 12,
 'RT_GROUP_ICON'   : 14,
 'RT_VERSION'      : 16,
 'RT_DLGINCLUDE'   : 17,
 'RT_PLUGPLAY'     : 19,
 'RT_VXD'          : 20,
 'RT_ANICURSOR'    : 21,
 'RT_ANIICON'      : 22,
 'RT_HTML'         : 23,
}

class VerInfo(procdump.ProcExeDump):
    """Prints out the version information from PE images"""

    def __init__(self, config, *args, **kwargs):
        procdump.ProcExeDump.__init__(self, config, *args, **kwargs)
        config.remove_option("OFFSET")
        config.remove_option("PID")
        config.add_option("OFFSET", short_option = "o", type = 'int',
                          help = "Offset of the module to print the version information for")
        config.add_option('REGEX', short_option = "r", default = None,
                          help = 'Dump modules matching REGEX')
        config.add_option('IGNORE-CASE', short_option = 'i', action = 'store_true',
                      help = 'ignore case in pattern match', default = False)

    def calculate(self):
        """Returns a unique list of modules"""
        addr_space = utils.load_as(self._config)
        for cls in [_IMAGE_RESOURCE_DIRECTORY, _IMAGE_RESOURCE_DIR_STRING_U, _VS_FIXEDFILEINFO, _VS_VERSION_INFO, VerStruct]:
            addr_space.profile.object_classes[cls.__name__] = cls
        addr_space.profile.add_types(ver_types)

        if self._config.REGEX is not None:
            try:
                if self._config.IGNORE_CASE:
                    module_pattern = re.compile(self._config.REGEX, flags = sre_constants.SRE_FLAG_IGNORECASE)
                else:
                    module_pattern = re.compile(self._config.REGEX)
            except sre_constants.error, e:
                debug.error('Regular expression parsing error: {0}'.format(e))

        if self._config.OFFSET is not None:
            if not addr_space.is_valid_address(self._config.OFFSET):
                debug.error("Specified offset is not valid for the provided address space")
            yield addr_space, self._config.OFFSET
            raise StopIteration

        tasks = win32.tasks.pslist(addr_space)

        for task in tasks:
            for m in task.get_load_modules():
                if self._config.REGEX is not None:
                    if not (module_pattern.search(str(m.FullDllName))
                            or module_pattern.search(str(m.BaseDllName))):
                        continue

                yield task.get_process_address_space(), m

    def display_unicode(self, string):
        """Renders a UTF16 string"""
        if string is None:
            return ''
        return string.decode("utf16", "ignore").encode("ascii", 'backslashreplace')

    def get_version_info(self, addr_space, offset):
        """Accepts an address space and an executable image offset
        
           Returns a VS_VERSION_INFO object of NoneObject
        """
        if not addr_space.is_valid_address(offset):
            return obj.NoneObject("Disk image not resident in memory")

        try:
            nt_header = self.get_nt_header(addr_space = addr_space,
                                       base_addr = offset)
        except ValueError, ve:
            return obj.NoneObject("PE file failed initial sanity checks: {0}".format(ve))
        except exceptions.SanityCheckException, ve:
            return obj.NoneObject("PE file failed initial sanity checks: {0}. Try -u or --unsafe".format(ve))

        # header = s.read(m.DllBase, nt_header.OptionalHeader.SizeOfHeaders)

        for sect in nt_header.get_sections(self._config.UNSAFE):
            if str(sect.Name) == '.rsrc':
                root = obj.Object("_IMAGE_RESOURCE_DIRECTORY", offset + sect.VirtualAddress, addr_space)
                for rname, rentry, rdata in root.get_entries():
                    # We're a VERSION resource and we have subelements
                    if rname == resource_types['RT_VERSION'] and rentry:
                        for sname, sentry, sdata in rdata.get_entries():
                            # We're the single sub element of the VERSION
                            if sname == 1 and sentry:
                                # Get the string tables
                                for _stname, stentry, stdata in sdata.get_entries():
                                    if not stentry:
                                        return obj.Object("_VS_VERSION_INFO", offset = (stdata.DataOffset + offset), vm = addr_space)

    def render_text(self, outfd, data):
        """Renders the text"""
        for s, m in data:
            outfd.write(str(m.FullDllName))
            outfd.write("\n")
            vinfo = self.get_version_info(s, m.DllBase)
            if vinfo != None:
                outfd.write("  File version    : {0}\n".format(vinfo.FileInfo.file_version()))
                outfd.write("  Product version : {0}\n".format(vinfo.FileInfo.product_version()))
                outfd.write("  Flags           : {0}\n".format(vinfo.FileInfo.flags()))
                outfd.write("  OS              : {0}\n".format(vinfo.FileInfo.FileOS))
                outfd.write("  File Type       : {0}\n".format(vinfo.FileInfo.file_type()))
                outfd.write("  File Date       : {0}\n".format(vinfo.FileInfo.FileDate or ''))
                for name, children in vinfo.get_children():
                    if name == 'StringFileInfo':
                        for _codepage, strings in children:
                            for string, value in strings:
                                # Make sure value isn't a generator, and we've a subtree to deal with
                                if isinstance(value, type(strings)):
                                    outfd.write("  {0} : Subtrees not yet implemented\n".format(string))
                                else:
                                    outfd.write("  {0} : {1}\n".format(string, self.display_unicode(value)))
