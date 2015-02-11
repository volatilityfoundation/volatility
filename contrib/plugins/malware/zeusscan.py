# Volatility
#
# Zeus support:
# Michael Hale Ligh <michael.ligh@mnin.org>
#
# Citadel support:
# Santiago Vicente <smvicente@invisson.com>
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

import struct, hashlib
import volatility.utils as utils
import volatility.obj as obj
import volatility.commands as commands
import volatility.debug as debug
import volatility.win32.tasks as tasks
import volatility.plugins.malware.impscan as impscan
import volatility.plugins.taskmods as taskmods
import volatility.plugins.procdump as procdump
import volatility.addrspace as addrspace
import volatility.plugins.vadinfo as vadinfo
import volatility.exceptions as exceptions

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

RC4_KEYSIZE = 0x102

#--------------------------------------------------------------------------------
# Profile Modifications 
#--------------------------------------------------------------------------------

class ZeusVTypes(obj.ProfileModification):

    conditions = {'os': lambda x: x == 'windows', 
                  'memory_model': lambda x: x == "32bit"}
    
    def modification(self, profile):
        profile.vtypes.update({
            '_ZEUS2_CONFIG' : [ 0x1E6, {
                'struct_size' :   [ 0x0, ['unsigned int']], 
                'guid' :   [ 0x4, ['array', 0x30, ['unsigned short']]], 
                'guid2' : [ 0x7C, ['array', 0x10, ['unsigned char']]], 
                'rc4key' : [ 0x8C, ['array', 0x100, ['unsigned char']]], 
                'exefile' : [ 0x18E, ['String', dict(length = 0x14)]], 
                'datfile' : [ 0x1A2, ['String', dict(length = 0x14)]], 
                'keyname' : [ 0x1B6, ['String', dict(length = 0xA)]], 
                'value1' : [ 0x1C0, ['String', dict(length = 0xA)]],  
                'value2' : [ 0x1CA, ['String', dict(length = 0xA)]], 
                'value3' : [ 0x1D4, ['String', dict(length = 0xA)]], 
                'guid_xor_key' : [ 0x1DE, ['unsigned int']], 
                'xorkey' : [ 0x1E2, ['unsigned int']], 
            }], 
            '_CITADEL1345_CONFIG' : [ 0x11C, {
                'struct_size' :   [ 0x0, ['unsigned int']], 
                'guid' :   [ 0x4, ['array', 0x30, ['unsigned short']]], 
                'guid2' : [ 0x7C, ['array', 0x10, ['unsigned char']]], 
                'exefile' : [ 0x9C, ['String', dict(length = 0x14)]], 
                'datfile' : [ 0xB0, ['String', dict(length = 0x14)]], 
                'keyname' : [ 0xEC, ['String', dict(length = 0xA)]], 
                'value1' : [ 0xF6, ['String', dict(length = 0xA)]],  
                'value2' : [ 0x100, ['String', dict(length = 0xA)]], 
                'value3' : [ 0x10A, ['String', dict(length = 0xA)]], 
                'guid_xor_key' : [ 0x114, ['unsigned int']], 
                'xorkey' : [ 0x118, ['unsigned int']], 
                }],
            })

#--------------------------------------------------------------------------------
# Scanner for Zeus > 1.20 and < 2.0  
#--------------------------------------------------------------------------------

class ZeusScan1(taskmods.DllList):
    """Locate and Decrypt Zeus > 1.20 and < 2.0 Configs"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('memory_model', '32bit') == '32bit')

    def _zeus_filter(self, vad):
        """
        This is a callback that's executed by get_vads() 
        when searching for zeus injections. 

        @param vad: an MMVAD object.

        @returns: True if the MMVAD looks like it might
        contain a zeus image. 

        We want the memory to be executable, but right now we 
        can only get the original protection not the current 
        protection...and the original protection can be 
        anything. This version of zeus happens to use 
        PAGE_NOACCESS so that's what we'll look for instead.
        """

        prot = vad.u.VadFlags.Protection.v()
        prot = vadinfo.PROTECT_FLAGS.get(prot, "")

        return (vad.u.VadFlags.PrivateMemory == 0 and 
                    prot == "PAGE_NO_ACCESS" and 
                    vad.Tag == "VadS")

    def calculate(self):
        
        addr_space = utils.load_as(self._config)

        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            task_space = task.get_process_address_space()

            # We must have a process AS
            if not task_space:
                continue 

            winsock = None

            # Locate the winsock DLL
            for mod in task.get_load_modules():
                if str(mod.BaseDllName or '').lower() == "ws2_32.dll":
                    winsock = mod
                    break
            
            if not winsock:
                continue 

            # Resolve the closesocket API 
            closesocket = winsock.getprocaddress("closesocket")

            if not closesocket:
                continue 

            for vad, process_space in task.get_vads(
                                    vad_filter = self._zeus_filter,
                                    ):
                                    
                if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, 
                        vm = process_space).e_magic != 0x5A4D:
                    continue
                    
                data = process_space.zread(vad.Start, vad.Length)
            
                scanner = impscan.ImpScan(self._config).call_scan
                calls = list(scanner(task_space, vad.Start, data))

                for (_, iat_loc, call_dest) in calls:
                    if call_dest != closesocket:
                        continue 

                    # Read the DWORD directly after closesocket 
                    struct_base = obj.Object('Pointer', 
                        offset = iat_loc + 4, vm = task_space)

                    # To be valid, it must point within the vad segment 
                    if (struct_base < vad.Start or 
                            struct_base > (vad.Start + vad.End)):
                        continue 

                    # Grab the key data
                    key = task_space.read(struct_base + 0x2a, RC4_KEYSIZE)

                    # Greg's sanity check
                    if len(key) != RC4_KEYSIZE or key[-2:] != "\x00\x00":
                        continue

                    yield task, struct_base, key

    def render_text(self, outfd, data):

        for task, struct_base, key in data:
            hex = "\n".join(["{0:#010x}  {1:<48}  {2}".format(
                            struct_base + 0x2a + o, 
                            h, ''.join(c)) for o, h, c in utils.Hexdump(key)
                            ])
            outfd.write("Process: {0} {1}\n".format(
                task.UniqueProcessId, task.ImageFileName))
            outfd.write(hex)
            outfd.write("\n")

#--------------------------------------------------------------------------------
# Scanner for Zeus >= 2.0 
#--------------------------------------------------------------------------------

class ZeusScan2(procdump.ProcDump):
    """Locate and Decrypt Zeus >= 2.0 Configs"""

    signatures = {
    'namespace1':'rule z1 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',
    'namespace5':'rule z5 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ??} condition: $a}',
    'namespace2':'rule z2 {strings: $a = {55 8B EC 51 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 56 8D 34 01 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',
    'namespace3':'rule z3 {strings: $a = {68 02 01 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}',
    'namespace4':'rule z4 {strings: $a = {68 02 01 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}'
    }

    magic_struct = '_ZEUS2_CONFIG'

    params = dict(
            # This contains the C2 URL, RC4 key for decoding 
            # local.ds and the magic buffer
            decoded_config = None,
            # This contains the hardware lock info, the user.ds 
            # RC4 key, and XOR key
            encoded_magic = None,
            # The decoded version of the magic structure
            decoded_magic = None, 
            # The key for decoding the configuration
            config_key = None, 
            # The login key (citadel only)
            login_key = None, 
            # The AES key (citadel only)
            aes_key = None, 
            )

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('memory_model', '32bit') == '32bit')

    def rc4(self, key, encoded):
        """Perform a basic RC4 operation"""
        # Turn the buffers into lists so the elements are mutable
        key_copy = [ord(c) for c in key]
        enc_copy = [ord(c) for c in encoded]
        # Start with the last two bytes in the key
        var1 = key_copy[0x100]
        var2 = key_copy[0x101]
        # Do the RC4 algorithm
        for i in range(0, len(enc_copy)):
            var1 += 1
            a = var1 & 0xFF
            b = key_copy[a]
            var2 += b
            var2 &= 0xFF
            key_copy[a]  = key_copy[var2]
            key_copy[var2] = b
            enc_copy[i] ^= key_copy[(key_copy[a] + b) & 0xFF]
        # Return the decoded bytes as a string
        decoded = [chr(c) for c in enc_copy]
        return ''.join(decoded)

    def rc4_init(self, data):
        """Initialize the RC4 keystate"""
        # The key starts off as a mutable list
        key = list()
        for i in range(0, 256):
            key.append(i)
        # Add the trailing two bytes
        key.append(0)
        key.append(0)
        # Make a copy of the data so its mutable also
        data_copy = [ord(c) for c in data]
        var1 = 0
        var2 = 0
        for i in range(0, 256):
            a = key[i]
            var2 += (data_copy[var1] + a)
            var2 &= 0xFF
            var1 += 1
            key[i] = key[var2]
            key[var2] = a
        # Return a copy of the key as a string
        return ''.join([chr(c) for c in key])

    def decode_config(self, encoded_config, last_sec_data):
        """Decode the config with data from the last PE section. 

        @param encoded_config: the encoded configuration
        @param last_sec_data: last PE section data. 
        """

        return ''.join([chr(ord(last_sec_data[i]) ^ ord(encoded_config[i])) 
                        for i in range(len(encoded_config))])

    def check_matches(self, task_space, vad, matches, last_sec_data):
        """Check the Yara matches and derive the encoded/decoded 
        config objects and magic structures. 

        @param task_space: the process AS
        @param vad: the containing MMVAD 
        @param matches: list of YARA hits 
        @param last_sec_data: buffer of the last PE section's data
        """

        hits = dict((m.rule, m.strings[0][0] + vad.Start) for m in matches)

        ## Do the magic 
        if 'z3' in hits:
            addr = obj.Object('unsigned long', offset = hits['z3'] + 30, vm = task_space)
            size = task_space.profile.get_obj_size(self.magic_struct)
            self.params['encoded_magic'] = task_space.read(addr, size)
        elif 'z4' in hits:
            addr = obj.Object('unsigned long', offset = hits['z4'] + 31, vm = task_space)
            size = task_space.profile.get_obj_size(self.magic_struct)
            self.params['encoded_magic'] = task_space.read(addr, size)
        else:
            return False 

        ## Do the config 
        if 'z1' in hits:
            addr = obj.Object('unsigned long', offset = hits['z1'] + 8, vm = task_space)
            size = obj.Object('unsigned long', offset = hits['z1'] + 2, vm = task_space)
            encoded_config = task_space.read(addr, size)
            self.params['decoded_config'] = self.decode_config(encoded_config, last_sec_data)
        elif 'z2' in hits:
            addr = obj.Object('Pointer', offset = hits['z2'] + 26, vm = task_space)
            encoded_config = task_space.read(addr.dereference(), 0x3c8)
            rc4_init = self.rc4_init(encoded_config)
            self.params['decoded_config'] = self.rc4(rc4_init, last_sec_data[2:])
        elif 'z5' in hits:
            addr = obj.Object('unsigned long', offset = hits['z5'] + 8, vm = task_space)
            size = obj.Object('unsigned long', offset = hits['z5'] + 2, vm = task_space)
            encoded_config = task_space.read(addr, size)
            self.params['decoded_config'] = self.decode_config(encoded_config, last_sec_data)
        else:
            return False 

        ## We found at least one of each category 
        return True
    
    def decode_magic(self, config_key):
        """Decode the magic structure using the configuration key. 
        
        @param config_key: the config RC4 key.
        """

        return self.rc4(config_key, self.params['encoded_magic'])

    def scan_key(self, task_space):
        """Find the offset of the RC4 key and use it to 
        decode the magic buffer. 

        @param task_space: the process AS
        """

        offset = 0
        found = False

        while offset < len(self.params['decoded_config']) - RC4_KEYSIZE:

            config_key = self.params['decoded_config'][offset:offset + RC4_KEYSIZE]
            decoded_magic = self.decode_magic(config_key)

            # When the first four bytes of the decoded magic buffer 
            # equal the size of the magic buffer, then we've found 
            # a winning RC4 key
            (struct_size,) = struct.unpack("=I", decoded_magic[0:4])

            if struct_size == task_space.profile.get_obj_size(self.magic_struct):
                found = True
                self.params['config_key'] = config_key
                self.params['decoded_magic'] = decoded_magic
                break

            offset += 1

        return found 

    def calculate(self):
        
        if not has_yara:
            debug.error("You must install yara")

        addr_space = utils.load_as(self._config)

        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources = self.signatures)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            task_space = task.get_process_address_space()

            # We must have a process AS
            if not task_space:
                continue 

            for vad, process_space in task.get_vads(): 
            
                if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, 
                        vm = process_space).e_magic != 0x5A4D:
                    continue
                    
                # a zeus range will never be more than 5 MB
                if vad.Length > 0x500000:
                    continue

                data = process_space.zread(vad.Start, vad.Length)
            
                # check for the signature with YARA, both hits must be present
                matches = rules.match(data = data)

                if len(matches) < 2:
                    continue

                try:
                    dos_header = obj.Object("_IMAGE_DOS_HEADER", 
                                    offset = vad.Start, vm = task_space)
                    nt_header = dos_header.get_nt_header()
                except (ValueError, exceptions.SanityCheckException):
                    continue 

                # There must be more than 2 sections 
                if nt_header.FileHeader.NumberOfSections < 2:
                    continue

                # Get the last PE section's data 
                sections = list(nt_header.get_sections())
                last_sec = sections[-1]
                last_sec_data = task_space.zread(
                                    (last_sec.VirtualAddress + vad.Start), 
                                    last_sec.Misc.VirtualSize
                                    )
                                    
                success = self.check_matches(task_space, vad, matches, 
                                            last_sec_data)

                if not success:
                    continue 

                success = self.scan_key(task_space)

                if not success:
                    continue 

                yield task, vad, self.params

    def render_extra(self, outfd, task, vad, params):
        """Show any Zeus specific fields"""

        rc4_offset = task.obj_vm.profile.get_obj_offset(self.magic_struct, 'rc4key')
        creds_key = params['decoded_magic'][rc4_offset:rc4_offset + RC4_KEYSIZE]

        outfd.write("{0:<30} : \n{1}\n".format("Credential RC4 key", 
                "\n".join(
                ["{0:#010x}  {1:<48}  {2}".format(vad.Start + o, h, ''.join(c))
                for o, h, c in utils.Hexdump(creds_key)
                ])))

    def render_text(self, outfd, data):
        """Render the plugin's default text output"""
        
        for task, vad, params in data:

            # Get a magic object from the buffer
            buffer_space = addrspace.BufferAddressSpace(
                                config = self._config, 
                                data = params['decoded_magic'])

            magic_obj = obj.Object(self.magic_struct, 
                                offset = 0, vm = buffer_space)

            outfd.write("*" * 50 + "\n")
            outfd.write("{0:<30} : {1}\n".format("Process", task.ImageFileName))
            outfd.write("{0:<30} : {1}\n".format("Pid", task.UniqueProcessId))
            outfd.write("{0:<30} : {1}\n".format("Address", vad.Start))

            # grab the URLs from the decoded buffer
            decoded_config = params['decoded_config']
            urls = []
            while "http" in decoded_config:
                url = decoded_config[decoded_config.find("http"):]
                urls.append(url[:url.find('\x00')])
                decoded_config = url[url.find('\x00'):]
            for i, url in enumerate(urls):
                outfd.write("{0:<30} : {1}\n".format("URL {0}".format(i), url))

            outfd.write("{0:<30} : {1}\n".format("Identifier", 
                ''.join([chr(c) for c in magic_obj.guid if c != 0])))
            outfd.write("{0:<30} : {1}\n".format("Mutant key", magic_obj.guid_xor_key))
            outfd.write("{0:<30} : {1}\n".format("XOR key", magic_obj.xorkey))
            outfd.write("{0:<30} : {1}\n".format("Registry", 
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\{0}".format(magic_obj.keyname)))
            outfd.write("{0:<30} : {1}\n".format(" Value 1", magic_obj.value1))
            outfd.write("{0:<30} : {1}\n".format(" Value 2", magic_obj.value2))
            outfd.write("{0:<30} : {1}\n".format(" Value 3", magic_obj.value3))
            outfd.write("{0:<30} : {1}\n".format("Executable", magic_obj.exefile))
            outfd.write("{0:<30} : {1}\n".format("Data file", magic_obj.datfile))

            outfd.write("{0:<30} : \n{1}\n".format("Config RC4 key", 
                    "\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(vad.Start + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(params['config_key'])
                    ])))

            self.render_extra(outfd, task, vad, params)

class CitadelScan1345(ZeusScan2):
    """Locate and Decrypt Citadel 1.3.4.5 Configs"""

    signatures = {
    'namespace1':'rule z1 {strings: $a = {8B EC 83 EC 0C 8A 82 ?? ?? ?? ?? 88 45 FE 8A 82 01 01 00 00 88 45 FD 8A 82 02 01 00 00 B9 ?? ?? ?? ?? 88 45 FF E8 ?? ?? ?? ??} condition: $a}',
    'namespace2':'rule z2 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ?? 8B F2 2B C8} condition: $a}',
    'namespace3':'rule z3 {strings: $a = {68 ?? ?? 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? 00 00 50 68 ?? ?? ?? ??} condition: $a}'
    }

    magic_struct = '_CITADEL1345_CONFIG'

    def rc4(self, key, encoded, login_key):
        """Perform a basic RC4 operation. 
        
        Same as Zeus, but with incorporation of
        a LOGIN_KEY value."""
        # Turn the buffers into lists so the elements are mutable
        key_copy = [ord(c) for c in key]
        enc_copy = [ord(c) for c in encoded]
        # Start with the last two bytes in the key
        var1 = key_copy[0x100]
        var2 = key_copy[0x101]
        var3 = 0
        login_key_len = len(login_key);
        # Do the RC4 algorithm
        for i in range(0, len(enc_copy)):
            var1 += 1
            a = var1 & 0xFF
            b = key_copy[a]
            var2 += b
            var2 &= 0xFF
            key_copy[a]  = key_copy[var2]
            key_copy[var2] = b
            enc_copy[i] ^= key_copy[(key_copy[a] + b) & 0xFF]
            enc_copy[i] ^= ord(login_key[var3])
            var3 += 1
            if (var3 == login_key_len):
                var3 = 0

        # Return the decoded bytes as a string
        decoded = [chr(c) for c in enc_copy]
        return ''.join(decoded)

    def decode_magic(self, config_key):
        """Decode the magic buffer using RC4 and 
        the LOGIN_KEY."""

        return self.rc4(config_key, self.params['encoded_magic'], 
                        self.params['login_key'])

    def check_matches(self, task_space, vad, matches, last_sec_data):
        """Check the Yara matches and derive the encoded/decoded 
        config objects and magic structures. 

        @param task_space: the process AS
        @param vad: the containing MMVAD 
        @param matches: list of YARA hits 
        @param last_sec_data: buffer of the last PE section's data
        """

        hits = dict((m.rule, m.strings[0][0] + vad.Start) for m in matches)

        if 'z1' in hits:
            addr = obj.Object('unsigned long', offset = hits['z1'] + 30, vm = task_space)
            self.params['login_key'] = task_space.read(addr, 0x20)
        else:
            return False

        if 'z2' in hits:
            addr = obj.Object('unsigned long', offset = hits['z2'] + 8, vm = task_space)
            size = obj.Object('unsigned long', offset = hits['z2'] + 2, vm = task_space)
            encoded_config = task_space.read(addr, size)
            self.params['decoded_config'] = self.decode_config(encoded_config, last_sec_data)
        else:
            return False

        if 'z3' in hits:
            addr = obj.Object('unsigned long', offset = hits['z3'] + 31, vm = task_space)
            size = task_space.profile.get_obj_size(self.magic_struct)
            self.params['encoded_magic'] = task_space.read(addr, size)
        else:
            return False

        return True

    def render_extra(self, outfd, task, vad, params):
        """Show Citadel specific fields"""

        aes_key = self.rc4(params['config_key'], 
                           hashlib.md5(params['login_key']).digest(),
                           params['login_key'])

        outfd.write("{0:<30} : {1}\n".format("Login key", params['login_key'].upper()))
        outfd.write("{0:<30} : {1}\n".format("AES key", str(aes_key).encode('hex').upper()))
