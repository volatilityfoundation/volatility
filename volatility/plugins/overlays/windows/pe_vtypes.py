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

import volatility.exceptions as exceptions
import volatility.obj as obj

pe_vtypes = {
    '_IMAGE_EXPORT_DIRECTORY': [ 0x28, {
    'Base': [ 0x10, ['unsigned int']],
    'NumberOfFunctions': [ 0x14, ['unsigned int']],
    'NumberOfNames': [ 0x18, ['unsigned int']],
    'AddressOfFunctions': [ 0x1C, ['unsigned int']],
    'AddressOfNames': [ 0x20, ['unsigned int']],
    'AddressOfNameOrdinals': [ 0x24, ['unsigned int']],
    }],
    '_IMAGE_IMPORT_DESCRIPTOR': [ 0x14, {
    # 0 for terminating null import descriptor
    'OriginalFirstThunk': [ 0x0, ['unsigned int']],
    'TimeDateStamp': [ 0x4, ['unsigned int']],
    'ForwarderChain': [ 0x8, ['unsigned int']],
    'Name': [ 0xC, ['unsigned int']],
    # If bound this has actual addresses
    'FirstThunk': [ 0x10, ['unsigned int']],
    }],
    '_IMAGE_THUNK_DATA' : [ 0x4, {
    # Fake member for testing if the highest bit is set
    'OrdinalBit' : [ 0x0, ['BitField', dict(start_bit = 31, end_bit = 32)]],
    'Function' : [ 0x0, ['pointer', ['void']]],
    'Ordinal' : [ 0x0, ['unsigned long']],
    'AddressOfData' : [ 0x0, ['unsigned int']],
    'ForwarderString' : [ 0x0, ['unsigned int']],
    }],
    '_IMAGE_IMPORT_BY_NAME' : [ None, {
    'Hint' : [ 0x0, ['unsigned short']],
    'Name' : [ 0x2, ['String', dict(length = 128)]],
    }],
}

pe_vtypes_64 = {
    '_IMAGE_THUNK_DATA' : [ 0x8, {
    # Fake member for testing if the highest bit is set
    'OrdinalBit' : [ 0x0, ['BitField', dict(start_bit = 63, end_bit = 64)]],
    'Function' : [ 0x0, ['pointer64', ['void']]],
    'Ordinal' : [ 0x0, ['unsigned long long']],
    'AddressOfData' : [ 0x0, ['unsigned long long']],
    'ForwarderString' : [ 0x0, ['unsigned long long']],
    }],
}

class _IMAGE_EXPORT_DIRECTORY(obj.CType):
    """Class for PE export directory"""

    def valid(self, nt_header):
        """
        Check the sanity of export table fields.

        The RVAs cannot be larger than the module size. The function
        and name counts cannot be larger than 32K. 
        """
        try:
            return (self.AddressOfFunctions < nt_header.OptionalHeader.SizeOfImage and
                    self.AddressOfNameOrdinals < nt_header.OptionalHeader.SizeOfImage and
                    self.AddressOfNames < nt_header.OptionalHeader.SizeOfImage and
                    self.NumberOfFunctions < 0x7FFF and
                    self.NumberOfNames < 0x7FFF)
        except obj.InvalidOffsetError:
            return False

    def _name(self, name_rva):
        """
        Return a String object for the function name.

        Names are truncated at 128 characters although its possible 
        they may be longer. Thus, infrequently a function name will
        be missing some data. However, that's better than hard-coding
        a larger value which frequently causes us to cross page 
        boundaries and return a NoneObject anyway.  
        """
        return obj.Object("String",
                      offset = self.obj_parent.DllBase + name_rva,
                      vm = self.obj_native_vm, length = 128)

    def _exported_functions(self):
        """
        Generator for exported functions.

        @return: tuple (Ordinal, FunctionRVA, Name)

        Ordinal is an integer and should never be None. If the function 
        is forwarded, FunctionRVA is None. Otherwise, FunctionRVA is an
        RVA to the function's code (relative to module base). Name is a
        String containing the exported function's name. If the Name is 
        paged, it will be None. If the function is forwarded, Name is the
        forwarded function name including the DLL (ntdll.EtwLogTraceEvent). 
        """

        mod_base = self.obj_parent.DllBase
        exp_dir = self.obj_parent.export_dir()

        # PE files with a large number of functions will have arrays
        # that spans multiple pages. Thus the first entries may be valid, 
        # last entries may be valid, but middle entries may be invalid
        # (paged). In the various checks below, we test for None (paged)
        # and zero (non-paged but invalid RVA). 

        # Array of RVAs to function code 
        address_of_functions = obj.Object('Array',
                                    offset = mod_base + self.AddressOfFunctions,
                                    targetType = 'unsigned int',
                                    count = self.NumberOfFunctions,
                                    vm = self.obj_native_vm)
        # Array of RVAs to function names 
        address_of_names = obj.Object('Array',
                                    offset = mod_base + self.AddressOfNames,
                                    targetType = 'unsigned int',
                                    count = self.NumberOfNames,
                                    vm = self.obj_native_vm)
        # Array of RVAs to function ordinals 
        address_of_name_ordinals = obj.Object('Array',
                                    offset = mod_base + self.AddressOfNameOrdinals,
                                    targetType = 'unsigned short',
                                    count = self.NumberOfNames,
                                    vm = self.obj_native_vm)

        # When functions are exported by Name, it will increase
        # NumberOfNames by 1 and NumberOfFunctions by 1. When 
        # functions are exported by Ordinal, only the NumberOfFunctions
        # will increase. First we enum functions exported by Name 
        # and track their corresponding Ordinals, so that when we enum
        # functions exported by Ordinal only, we don't duplicate. 

        seen_ordinals = []

        # Handle functions exported by name *and* ordinal 
        for i in range(self.NumberOfNames):

            name_rva = address_of_names[i]
            ordinal = address_of_name_ordinals[i]

            if name_rva in (0, None):
                continue

            # Check the sanity of ordinal values before using it as an index
            if ordinal == None or ordinal >= self.NumberOfFunctions:
                continue

            func_rva = address_of_functions[ordinal]

            if func_rva in (0, None):
                continue

            # Handle forwarded exports. If the function's RVA is inside the exports 
            # section (as given by the VirtualAddress and Size fields in the 
            # DataDirectory), the symbol is forwarded. Return the name of the 
            # forwarded function and None as the function address. 

            if (func_rva >= exp_dir.VirtualAddress and
                    func_rva < exp_dir.VirtualAddress + exp_dir.Size):
                n = self._name(func_rva)
                f = obj.NoneObject("Ordinal function {0} in module {1} forwards to {2}".format(
                                   ordinal, self.obj_parent.BaseDllName, n))
            else:
                n = self._name(name_rva)
                f = func_rva

            # Add the ordinal base and save it 
            ordinal += self.Base
            seen_ordinals.append(ordinal)

            yield ordinal, f, n

        # Handle functions exported by ordinal only 
        for i in range(self.NumberOfFunctions):

            ordinal = self.Base + i

            # Skip functions already enumberated above 
            if ordinal not in seen_ordinals:

                func_rva = address_of_functions[i]

                if func_rva in (0, None):
                    continue

                seen_ordinals.append(ordinal)

                # There is no name RVA 
                yield ordinal, func_rva, obj.NoneObject("Name RVA not accessible")

class _IMAGE_IMPORT_DESCRIPTOR(obj.CType):
    """Handles IID entries for imported functions"""

    def valid(self, nt_header):
        """Check the validity of some fields"""
        try:
            return (self.OriginalFirstThunk != 0 and
                    self.OriginalFirstThunk < nt_header.OptionalHeader.SizeOfImage and
                    self.FirstThunk != 0 and
                    self.FirstThunk < nt_header.OptionalHeader.SizeOfImage and
                    self.Name < nt_header.OptionalHeader.SizeOfImage)
        except obj.InvalidOffsetError:
            return False

    def _name(self, name_rva):
        """Return a String object for the name at the given RVA"""

        return obj.Object("String",
                      offset = self.obj_parent.DllBase + name_rva,
                      vm = self.obj_native_vm, length = 128)

    def dll_name(self):
        """Returns the name of the DLL for this IID"""
        return self._name(self.Name)

    def _imported_functions(self):
        """
        Generator for imported functions. 

        @return: tuple (Ordinal, FunctionVA, Name)

        If the function is imported by ordinal, then Ordinal is the 
        ordinal value and Name is None. 

        If the function is imported by name, then Ordinal is the
        hint and Name is the imported function name (or None if its
        paged). 

        FunctionVA is the virtual address of the imported function,
        as applied to the IAT by the Windows loader. If the FirstThunk
        is paged, then FunctionVA will be None. 
        """

        i = 0
        while 1:
            thunk = obj.Object('_IMAGE_THUNK_DATA',
                       offset = self.obj_parent.DllBase + self.OriginalFirstThunk +
                       i * self.obj_vm.profile.get_obj_size('_IMAGE_THUNK_DATA'),
                       vm = self.obj_native_vm)

            # We've reached the end when the element is zero 
            if thunk == None or thunk.AddressOfData == 0:
                break

            o = obj.NoneObject("Ordinal not accessible?")
            n = obj.NoneObject("Imported by ordinal?")
            f = obj.NoneObject("FirstThunk not accessible")

            # If the highest bit (32 for x86 and 64 for x64) is set, the function is 
            # imported by ordinal and the lowest 16-bits contain the ordinal value. 
            # Otherwise, the lowest bits (0-31 for x86 and 0-63 for x64) contain an 
            # RVA to an _IMAGE_IMPORT_BY_NAME struct. 
            if thunk.OrdinalBit == 1:
                o = thunk.Ordinal & 0xFFFF
            else:
                iibn = obj.Object("_IMAGE_IMPORT_BY_NAME",
                                  offset = self.obj_parent.DllBase +
                                  thunk.AddressOfData,
                                  vm = self.obj_native_vm)
                o = iibn.Hint
                n = iibn.Name

            # See if the import is bound (i.e. resolved)
            first_thunk = obj.Object('_IMAGE_THUNK_DATA',
                            offset = self.obj_parent.DllBase + self.FirstThunk +
                            i * self.obj_vm.profile.get_obj_size('_IMAGE_THUNK_DATA'),
                            vm = self.obj_native_vm)
            if first_thunk:
                f = first_thunk.Function.v()

            yield o, f, n
            i += 1

    def is_list_end(self):
        """Returns True if we've reached the list end"""
        data = self.obj_vm.zread(
                        self.obj_offset,
                        self.obj_vm.profile.get_obj_size('_IMAGE_IMPORT_DESCRIPTOR')
                        )
        return data.count(chr(0)) == len(data)

class _LDR_DATA_TABLE_ENTRY(obj.CType):
    """
    Class for PE file / modules

    If these classes are instantiated by _EPROCESS.list_*_modules() 
    then its guaranteed to be in the process address space. 

    FIXME: If these classes are found by modscan, ensure we can
    dereference properly with obj_native_vm. 
    """

    def _nt_header(self):
        """Return the _IMAGE_NT_HEADERS object"""

        try:
            dos_header = obj.Object("_IMAGE_DOS_HEADER", offset = self.DllBase,
                                    vm = self.obj_native_vm)

            return dos_header.get_nt_header()
        except ValueError:
            return obj.NoneObject("Failed initial sanity checks")
        except exceptions.SanityCheckException:
            return obj.NoneObject("Failed initial sanity checks. Try -u or --unsafe")

    def _directory(self, dir_index):
        """Return the requested IMAGE_DATA_DIRECTORY"""

        nt_header = self._nt_header()
        if nt_header == None:
            raise ValueError('No directory index {0}'.format(dir_index))

        data_dir = nt_header.OptionalHeader.DataDirectory[dir_index]
        if data_dir == None:
            raise ValueError('No directory index {0}'.format(dir_index))

        # Make sure the directory exists 
        if data_dir.VirtualAddress == 0 or data_dir.Size == 0:
            raise ValueError('No directory index {0}'.format(dir_index))

        # Make sure the directory VA and Size are sane 
        if data_dir.VirtualAddress + data_dir.Size > nt_header.OptionalHeader.SizeOfImage:
            raise ValueError('Invalid directory for index {0}'.format(dir_index))

        return data_dir

    def export_dir(self):
        """Return the IMAGE_DATA_DIRECTORY for exports"""
        return self._directory(0) # DIRECTORY_ENTRY_EXPORT

    def import_dir(self):
        """Return the IMAGE_DATA_DIRECTORY for imports"""
        return self._directory(1) # DIRECTORY_ENTRY_IMPORT

    def debug_dir(self):
        """Return the IMAGE_DEBUG_DIRECTORY for debug info"""
        return self._directory(6) # IMAGE_DEBUG_DIRECTORY

    def get_debug_directory(self):
        """Return the debug directory object for this PE"""
        
        try:
            data_dir = self.debug_dir()
        except ValueError, why:
            return obj.NoneObject(str(why))

        return obj.Object("_IMAGE_DEBUG_DIRECTORY", 
                          offset = self.DllBase + data_dir.VirtualAddress, 
                          vm = self.obj_native_vm)

    def getprocaddress(self, func):
        """Return the RVA of func"""
        for _, f, n in self.exports():
            if str(n or '') == func:
                return f
        return None

    def imports(self):
        """
        Generator for the PE's imported functions.

        The _DIRECTORY_ENTRY_IMPORT.VirtualAddress points to an array 
        of _IMAGE_IMPORT_DESCRIPTOR structures. The end is reached when 
        the IID structure is all zeros. 
        """

        try:
            data_dir = self.import_dir()
        except ValueError, why:
            raise StopIteration(why)

        i = 0

        desc_size = self.obj_vm.profile.get_obj_size('_IMAGE_IMPORT_DESCRIPTOR')

        while 1:
            desc = obj.Object('_IMAGE_IMPORT_DESCRIPTOR',
                      vm = self.obj_native_vm,
                      offset = self.DllBase + data_dir.VirtualAddress + (i * desc_size),
                      parent = self)

            # Stop if the IID is paged or all zeros
            if desc == None or desc.is_list_end():
                break

            # Stop if the IID contains invalid fields 
            if not desc.valid(self._nt_header()):
                break

            dll_name = desc.dll_name()

            for o, f, n in desc._imported_functions():
                yield dll_name, o, f, n

            i += 1

    def exports(self):
        """Generator for the PE's exported functions"""

        try:
            data_dir = self.export_dir()
        except ValueError, why:
            raise StopIteration(why)

        expdir = obj.Object('_IMAGE_EXPORT_DIRECTORY',
                            offset = self.DllBase + data_dir.VirtualAddress,
                            vm = self.obj_native_vm,
                            parent = self)

        if expdir.valid(self._nt_header()):
            # Ordinal, Function RVA, and Name Object 
            for o, f, n in expdir._exported_functions():
                yield o, f, n

class WinPEVTypes(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows'}
    def modification(self, profile):
        profile.vtypes.update(pe_vtypes)

class WinPEx64VTypes(obj.ProfileModification):
    before = ['WinPEVTypes']
    conditions = {'os': lambda x : x == 'windows',
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(pe_vtypes_64)

class WinPEObjectClasses(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows'}
    def modification(self, profile):
        profile.object_classes.update({
            '_IMAGE_EXPORT_DIRECTORY': _IMAGE_EXPORT_DIRECTORY,
            '_IMAGE_IMPORT_DESCRIPTOR': _IMAGE_IMPORT_DESCRIPTOR,
            '_LDR_DATA_TABLE_ENTRY': _LDR_DATA_TABLE_ENTRY,
            })
