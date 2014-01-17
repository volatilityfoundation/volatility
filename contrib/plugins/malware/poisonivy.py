# Poison Ivy RAT detection and analysis for Volatility 2.0
#
# Version 1.0 (for release at the FIRST Conference, June 18, 2012)
#
# This version is limited to PoisonIvy's server version 2.3.1 
#
# Author: Andreas Schuster <a.schuster@forensikblog.de>
#
# This plugin is based on zeusscan2.py by Michael Hale Ligh.
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

import volatility.plugins.taskmods as taskmods
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

class PIHOST(obj.CType):
    """Class for Poison Ivy Host/Proxy"""

    def next(self):
        """The next variable-length structure in the array"""

        return obj.Object("PIHOST", 
                         offset = self.obj_offset + self.length + 
                         self.obj_vm.profile.get_obj_size("PIHOST"), 
                         vm = self.obj_vm)

class PICONFIG(obj.CType):
    """Class for Poison Ivy Configuration Block"""

    def _read_hosts(self, memb):
        """Parse C2 or proxy config from data block"""

        # The first object in the array 
        host = obj.Object("PIHOST", offset = memb.obj_offset, vm = self.obj_vm)
        # The number of objects shall not exceed
        # the total size of the array 
        size = self.obj_vm.profile.get_obj_size("HOSTCFGSPACE")

        while (host.length > 0 and 
                    host.obj_offset < memb.obj_offset + size):
            yield host 
            host = host.next()

    def get_hosts(self):
        """Return the list of C2 hosts"""

        if self.ProxyCfgPresent == 1:
            return self._read_hosts(self.C2WhenProxy)
        else:
            return self._read_hosts(self.NextHop)

    def get_proxies(self):
        """Return the list of proxies"""        

        if self.ProxyCfgPresent == 1:
            return self._read_hosts(self.NextHop)
        else:
            raise StopIteration 

    @property
    def CopyDestFile(self):
        """Return the destination directory and file name"""

        destination = ''
        if self.CopyDestDir == 1:
            destination = '%WINDIR%'
        elif self.CopyDestDir == 2:
            destination = '%WINDIR%\\System32'

        if self.CopyAsADS == 1:
            destination += ':'
        else:
            destination += '\\' 

        return destination + self.m('CopyDestFile')

class PoisonIvyTypesx86(obj.ProfileModification):
    """Modification for Poison Ivy"""

    conditions = {'os': lambda x: x == 'windows', 
                  'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):

        profile.object_classes.update({'PIHOST': PIHOST, 'PICONFIG': PICONFIG})

        profile.vtypes.update({
            'PIHOST': [ 4, { # minimum size based on the static fields 
                'length'                       : [ 0, ['unsigned char']], 
                'hostname'                     : [ 1, ['String', dict(length = lambda x : x.length)]], 
                'proto'                        : [ lambda x: x.obj_offset + 1 + x.length, ['Enumeration', dict(target = 'unsigned char', choices = {0: 'direct', 1: 'SOCKS', 2: 'HTTP'})]], 
                'port'                         : [ lambda x: x.obj_offset + 1 + x.length + 1, ['unsigned short']], 
            }], 
            'HOSTCFGSPACE' : [ 256, {
            }],
            'PICONFIG' : [ 0xf74, {
                'imp_socket'                   : [ 0x001, ['unsigned int']],
                'imp_connect'                  : [ 0x005, ['unsigned int']],
                'imp_closesocket'              : [ 0x009, ['unsigned int']],
                'imp_send'                     : [ 0x00d, ['unsigned int']],
                'imp_recv'                     : [ 0x011, ['unsigned int']],
                'imp_htons'                    : [ 0x015, ['unsigned int']],
                'imp_inet_addr'                : [ 0x019, ['unsigned int']],
                'imp_gethostbyname'            : [ 0x01d, ['unsigned int']],
                'imp_VirtualAlloc'             : [ 0x021, ['unsigned int']],
                'imp_VirtualFree'              : [ 0x025, ['unsigned int']],
                'imp_CreateThread'             : [ 0x029, ['unsigned int']],
                'imp_CreateProcessA'           : [ 0x02d, ['unsigned int']],
                'imp_RegCloseKey'              : [ 0x031, ['unsigned int']],
                'imp_RegOpenKeyExA'            : [ 0x035, ['unsigned int']],
                'imp_RegQueryValueExA'         : [ 0x039, ['unsigned int']],
                'imp_RegSetValueExA'           : [ 0x03d, ['unsigned int']],
                'imp_RegDeleteKeyA'            : [ 0x041, ['unsigned int']],
                'imp_RegCreateKeyExA'          : [ 0x045, ['unsigned int']],
                'imp_RegQueryInfoKeyA'         : [ 0x049, ['unsigned int']],
                'imp_RegEnumKeyExA'            : [ 0x04d, ['unsigned int']],
                'imp_DeleteFileA'              : [ 0x051, ['unsigned int']],
                'imp_CopyFileA'                : [ 0x055, ['unsigned int']],
                'imp_CreateFileA'              : [ 0x059, ['unsigned int']],
                'imp_GetKeyNameTextA'          : [ 0x05d, ['unsigned int']],
                'imp_GetActiveWindow'          : [ 0x061, ['unsigned int']],
                'imp_GetWindowTextA'           : [ 0x065, ['unsigned int']],
                'imp_WriteFile'                : [ 0x069, ['unsigned int']],
                'imp_CallNextHookEx'           : [ 0x06d, ['unsigned int']],
                'imp_SetFilePointer'           : [ 0x071, ['unsigned int']],
                'imp_ToAscii'                  : [ 0x075, ['unsigned int']],
                'imp_GetKeyboardState'         : [ 0x079, ['unsigned int']],
                'imp_GetLocalTime'             : [ 0x07d, ['unsigned int']],
                'imp_lstrcat'                  : [ 0x081, ['unsigned int']],
                'imp_CreateMutexA'             : [ 0x085, ['unsigned int']],
                'imp_RtlGetLastWin32Error'     : [ 0x089, ['unsigned int']],
                'imp_GetFileTime'              : [ 0x08d, ['unsigned int']],
                'imp_SetFileTime'              : [ 0x091, ['unsigned int']],
                'imp_OpenProcess'              : [ 0x095, ['unsigned int']],
                'imp_select'                   : [ 0x099, ['unsigned int']],
                'imp_LoadLibraryA'             : [ 0x09d, ['unsigned int']],
                'imp_CloseHandle'              : [ 0x0a1, ['unsigned int']],
                'imp_Sleep'                    : [ 0x0a5, ['unsigned int']],
                'imp_RtlMoveMemory'            : [ 0x0a9, ['unsigned int']],
                'imp_RtlZeroMemory'            : [ 0x0ad, ['unsigned int']],
                'imp_VirtualAllocEx'           : [ 0x0b1, ['unsigned int']],
                'imp_WriteProcessMemory'       : [ 0x0b5, ['unsigned int']],
                'imp_CreateToolhelp32Snapshot' : [ 0x0b9, ['unsigned int']],
                'imp_Process32First'           : [ 0x0bd, ['unsigned int']],
                'imp_Process32Next'            : [ 0x0c1, ['unsigned int']],
                'func_FindProcess'             : [ 0x0c5, ['unsigned int']],
                'imp_CreateRemoteThread'       : [ 0x0c9, ['unsigned int']],
                'imp_lstrcmpi'                 : [ 0x0cd, ['unsigned int']],
                'func_WriteProcess'            : [ 0x0d1, ['unsigned int']],
                'func_Extra'                   : [ 0x0d5, ['unsigned int']],
                'func_Main'                    : [ 0x0d9, ['unsigned int']],
                'func_GetProcAddressByCRC32'   : [ 0x0dd, ['unsigned int']],
                'NULL'                         : [ 0x0e1, ['unsigned int']],
                'func_Send_Receive'            : [ 0x0e5, ['unsigned int']],
                'func_strcopy'                 : [ 0x0e9, ['unsigned int']],
                'func_Keylogger_Hook'          : [ 0x0ed, ['unsigned int']],
                'func_0f1'                     : [ 0x0f1, ['unsigned int']],
                'func_Persist_ActiveSetup'     : [ 0x0f5, ['unsigned int']],
                'func_Injector'                : [ 0x0f9, ['unsigned int']],
                'func_Key_expansion'           : [ 0x0fd, ['unsigned int']],
                'func_Encrypt'                 : [ 0x101, ['unsigned int']],
                'func_Decrypt'                 : [ 0x105, ['unsigned int']],
                'func_Camellia_feistel'        : [ 0x109, ['unsigned int']],
                'func_Camellia_local'          : [ 0x10d, ['unsigned int']],
                'var_Camellia_Sbox1'           : [ 0x111, ['unsigned int']],
                'var_Camellia_Table1'          : [ 0x115, ['unsigned int']],
                'var_Camellia_Table2'          : [ 0x119, ['unsigned int']],
                'var_Socket'                   : [ 0x121, ['unsigned int']],
                'var_Version'                  : [ 0x129, ['unsigned int']],
                'CopyDestFile'                 : [ 0x12d, ['String', dict(length = 24)]],
                'Secret'                       : [ 0x145, ['String', dict(length = 32)]],
                'PersistActiveSetupGUID'       : [ 0x165, ['String', dict(length = 38)]],
                'NextHop'                      : [ 0x190, ['HOSTCFGSPACE']],
                'ProxyCfgPresent'              : [ 0x2c1, ['int']],
                'C2WhenProxy'                  : [ 0x2c5, ['HOSTCFGSPACE']],
                'PersistActiveSetupOn'         : [ 0x3f6, ['unsigned char']],
                'CopyDestDir'                  : [ 0x3f7, ['unsigned char']],
                'Melt'                         : [ 0x3f8, ['unsigned char']],
                'InjectPersist'                : [ 0x3f9, ['unsigned char']],
                'Keylogger'                    : [ 0x3fa, ['unsigned char']],
                'Mutex'                        : [ 0x3fb, ['String', dict(length = 20)]],
                'PersistActiveSetupName'       : [ 0x40f, ['String', dict(length = 9)]],
                'DefaultBrowserKey'            : [ 0x418, ['String', dict(length = 41)]],
                'InjectIntoDefaultBrowser'     : [ 0x441, ['unsigned char']],
                'InjectIntoProcessName'        : [ 0x442, ['String', dict(length = 20)]],
                'PersistActiveSetupKeyPart'    : [ 0x456, ['String', dict(length = 93)]],
                'PersistActiveSetupKey'        : [ 0x4b3, ['String', dict(length = 255)]],
                'CurrentFile'                  : [ 0x5b2, ['String', dict(length = 255)]],
                'PersistentFile'               : [ 0x6b1, ['String', dict(length = 255)]],
                'KeyloggerLogfile'             : [ 0x7b0, ['String', dict(length = 255)]],
                'IsAdmin'                      : [ 0x8af, ['unsigned char']],
                'var_8b4'                      : [ 0x8b4, ['unsigned int']],
                'var_8b8'                      : [ 0x8b8, ['unsigned char']],
                'var_8b9'                      : [ 0x8b9, ['unsigned int']],
                'KeyloggerTID'                 : [ 0x8bd, ['unsigned int']],
                'InjectorTID'                  : [ 0x8c1, ['unsigned int']],
                'hnd_Mutex'                    : [ 0x8c5, ['unsigned int']],
                'Challenge'                    : [ 0x8d9, ['array', 136, ['unsigned char']]],
                'var_Camellia_Keyschedule'     : [ 0x96b, ['array', 272, ['unsigned char']]],
                'hnd_Kernel32'                 : [ 0xabb, ['unsigned int']],
                'hnd_User32'                   : [ 0xabf, ['unsigned int']],
                'hnd_Ws2_32'                   : [ 0xac3, ['unsigned int']],
                'hnd_Advapi32'                 : [ 0xad3, ['unsigned int']],
                'hnd_Ntdll'                    : [ 0xadb, ['unsigned int']],
                'imp_lstrlenA'                 : [ 0xaf0, ['unsigned int']],
                'UseProxy'                     : [ 0xaf4, ['unsigned char']],
                'ProxyNoPersist'               : [ 0xaf5, ['unsigned char']],
                'func_af6'                     : [ 0xaf6, ['unsigned int']],
                'ServerId'                     : [ 0xafa, ['String', dict(length = 255)]],
                'ServerGroup'                  : [ 0xbf9, ['String', dict(length = 255)]],
                'imp_GetFileSize'              : [ 0xcf8, ['unsigned int']],
                'imp_ReadFile'                 : [ 0xcfc, ['unsigned int']],
                'func_CopyFile'                : [ 0xd00, ['unsigned int']],
                'func_Inject_explorer'         : [ 0xd04, ['unsigned int']],
                'Inject'                       : [ 0xd08, ['unsigned char']],
                'PersistHKLMRun'               : [ 0xd09, ['unsigned char']],
                'func_Persist_HKLMRun'         : [ 0xd0a, ['unsigned int']],
                'func_Keylogger'               : [ 0xd0e, ['unsigned int']],
                'CopyAsADS'                    : [ 0xd12, ['unsigned char']],
                'PersistHKLMRunName'           : [ 0xe12, ['String', dict(length = 255)]]
            }]
        })

# This simple signature is based on string constants. It it easy to find, easy
# to explain - and easy to break! Therefore you're advised to develop robust, 
# code based signatures for daily work.
signatures = {
    'namespace1' : 'rule pivars {strings: $a = { \
        53 74 75 62 50 61 74 68 ?? 53 4F 46 54 57 41 52\
        45 5C 43 6C 61 73 73 65 73 5C 68 74 74 70 5C 73\
        68 65 6C 6C 5C 6F 70 65 6E 5C 63 6F 6D 6D 61 6E\
        64 [22] 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F\
        73 6F 66 74 5C 41 63 74 69 76 65 20 53 65 74 75\
        70 5C 49 6E 73 74 61 6C 6C 65 64 20 43 6F 6D 70\
        6F 6E 65 6E 74 73 5C } condition: $a}'
}

class PoisonIvyScan(taskmods.DllList):
    "Detect processes infected with Poison Ivy"

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('memory_model', '32bit') == '32bit')

    def get_vad_base(self, task, address):
        """ Get the VAD starting address """        

        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start

        # This should never really happen
        return None

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)
        
        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")
        
        rules = yara.compile(sources = signatures)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task = task, rules = rules)

            for hit, address in scanner.scan():
                vad_base_addr = self.get_vad_base(task, address)
                if address - vad_base_addr > 0x1000:
                    continue

                yield task, vad_base_addr

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Name", "20"), 
                                  ("PID", "8"),
                                  ("Data VA", "[addrpad]")])

        for task, start in data:
            self.table_row(outfd, task.ImageFileName, task.UniqueProcessId, start)

class PoisonIvyConfig(PoisonIvyScan):
    "Locate and parse the Poison Ivy configuration"

    def render_text(self, outfd, data):
        
        delim = '-' * 80

        for task, start in data:

            outfd.write("{0}\n".format(delim))
            
            proc_addr_space = task.get_process_address_space()

            config = obj.Object('PICONFIG', offset = start, vm = proc_addr_space)

            outfd.write('Process: {0} ({1})\n\n'.format(task.ImageFileName, task.UniqueProcessId))
            outfd.write('Infection:\n')

            if config.IsAdmin == 1:
                outfd.write('\tPoisonIvy has ADMIN privileges!\n')
            else:
                outfd.write('\tPoisonIvy has user privileges.\n')

            outfd.write('\tVersion: {0}\n'.format(config.var_Version))
            outfd.write('\tBase VA: {0:#x}\n'.format(config.func_Main))
            outfd.write('\tExtra VA: {0:#x}\n'.format(config.func_Extra))
            outfd.write('\tData VA: {0:#x}\n'.format(start))
            outfd.write('\tMutex: {0}\n'.format(config.Mutex))
            outfd.write('\tOriginal file: {0}\n'.format(config.CurrentFile))
            outfd.write('\tMelt original file: {0}\n\n'.format(config.Melt == 1))

            outfd.write("Command and Control:\n")
            for i, host in enumerate(config.get_hosts()):
                outfd.write('\tHost {0}: {1}:{2} ({3})\n'.format(i, host.hostname, host.port, host.proto))

            # secret (either password or keyfile)
            if config.Secret.isalnum():
                outfd.write('\tPassword: {0}\n'.format(config.Secret))
            else:
                outfd.write('\tKey (from file): 0x{0}'.format(config.Secret.encode('hex')))

            # management info
            outfd.write('\tId: {0}\n'.format(config.ServerId))
            outfd.write('\tGroup: {0}\n\n'.format(config.ServerGroup))

            outfd.write('Keylogger:\n')
            outfd.write('\tKeylogger: {0}\n'.format(config.Keylogger == 1))
            if config.Keylogger == 1:
                outfd.write('\tKeylogger TID: {0}\n'.format(config.KeyloggerTID))
                outfd.write('\tKeylogger Setup: {0:#x}\n'.format(config.func_Keylogger))
                outfd.write('\tKeylogger Routine: {0:#x}\n'.format(config.func_Keylogger_Hook))
                outfd.write('\tKeylogger logfile: {0}\n'.format(config.KeyloggerLogfile))

            outfd.write("\nCopy file:\n")
            outfd.write('\tCopy routine: {0:#x}\n'.format(config.func_CopyFile))
            outfd.write('\tDestination: {0}\n'.format(config.CopyDestFile))

            outfd.write("\nPersistence:\n")
            outfd.write('\tActive Setup: {0}\n'.format(config.PersistActiveSetupOn == 1))
            if config.PersistActiveSetupOn == 1:
                outfd.write('\tActive Setup key: {0}\n'.format(config.PersistActiveSetupKey))
                outfd.write('\tActive Setup name: {0}\n'.format(config.PersistActiveSetupName))
                outfd.write('\tSetup routine: {0:#x}\n'.format(config.func_Persist_ActiveSetup))

            outfd.write("\tHKLM Run: {0}\n".format(bool(config.PersistHKLMRun == 1)))
            if config.PersistHKLMRun == 1:
                outfd.write("\tHKLM Run name: {0}\n".format(config.PersistHKLMRunName))
                outfd.write("\tSetup routine: {0:#x}\n".format(config.func_Persist_HKLMRun))

            outfd.write("\nInjector:\n")
            outfd.write("\tInject into other processes: {0}\n".format(config.Inject == 1))
            if config.Inject == 1:
                outfd.write('\tPersistently: {0}\n'.format(config.InjectPersist == 1))
                outfd.write('\tInjector TID: {0}\n'.format(config.InjectorTID))
                outfd.write('\tInjector Routine: {0:#x}\n'.format(config.func_Injector))
                outfd.write('\tTarget process name: {0}\n'.format(config.InjectIntoProcessName))
                outfd.write('\tTarget default browser: {0}\n'.format(config.InjectIntoDefaultBrowser == 1))

            outfd.write("\nProxy:\n")
            outfd.write('\tUse Proxy: {0}\n'.format(config.UseProxy == 1))
            if config.UseProxy == 1:
                outfd.write('\tPersistently: {0}\n'.format(config.ProxyNoPersist == 0))
                for i, proxy in enumerate(config.get_proxies()):
                    outfd.write('\tHost {0}: {1}:{2} ({3})\n'.format(i, proxy.hostname, proxy.port, proxy.proto))

            outfd.write("\nDecrypt: {0:#x}\n".format(config.func_Decrypt))
