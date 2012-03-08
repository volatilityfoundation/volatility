# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import volatility.win32.hive as hive
import volatility.win32.rawreg as rawreg
import volatility.win32.lsasecrets as lsasecrets
import volatility.win32.hashdump as hashdumpmod
import volatility.debug as debug
import volatility.cache as cache
import volatility.utils as utils
import volatility.commands as commands

class LSADump(commands.Command):
    """Dump (decrypted) LSA secrets from the registry"""
    # Declare meta information associated with this plugin

    meta_info = commands.Command.meta_info
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option('SYS-OFFSET', short_option = 'y', type = 'int',
                          help = 'SYSTEM hive offset (virtual)')
        config.add_option('SEC-OFFSET', short_option = 's', type = 'int',
                          help = 'SECURITY hive offset (virtual)')

    @cache.CacheDecorator(lambda self: "tests/lsadump/sys_offset={0}/sec_offset={1}".format(self._config.SYS_OFFSET, self._config.SEC_OFFSET))
    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self._config.sys_offset or not self._config.sec_offset:
            debug.error("Both SYSTEM and SECURITY offsets must be provided")

        secrets = lsasecrets.get_memory_secrets(addr_space, self._config, self._config.sys_offset, self._config.sec_offset)
        if not secrets:
            debug.error("Unable to read LSA secrets from registry")

        return secrets

    def render_text(self, outfd, data):
        for k in data:
            outfd.write(k + "\n")
            for offset, hex, chars in utils.Hexdump(data[k]):
                outfd.write("{0:#010x}  {1:<48}  {2}\n".format(offset, hex, ''.join(chars)))
            outfd.write("\n")

class HashDump(commands.Command):
    """Dumps passwords hashes (LM/NTLM) from memory"""

    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option('SYS-OFFSET', short_option = 'y', type = 'int',
                          help = 'SYSTEM hive offset (virtual)')
        config.add_option('SAM-OFFSET', short_option = 's', type = 'int',
                          help = 'SAM hive offset (virtual)')

    @cache.CacheDecorator(lambda self: "tests/hashdump/sys_offset={0}/sam_offset={1}".format(self._config.SYS_OFFSET, self._config.SAM_OFFSET))
    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self._config.sys_offset or not self._config.sam_offset:
            debug.error("Both SYSTEM and SAM offsets must be provided")

        return hashdumpmod.dump_memory_hashes(addr_space, self._config, self._config.sys_offset, self._config.sam_offset)

    def render_text(self, outfd, data):
        for d in data:
            if d == None:
                debug.error("Unable to read hashes from registry")
            outfd.write(d + "\n")

class HiveDump(commands.Command):
    """Prints out a hive"""
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o', type = 'int',
                          help = 'Hive offset (virtual)')

    @cache.CacheDecorator(lambda self: "tests/hivedump/hive_offset={0}".format(self._config.HIVE_OFFSET))
    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self._config.hive_offset:
            debug.error("A Hive offset must be provided (--hive-offset)")

        h = hive.HiveAddressSpace(addr_space, self._config, self._config.hive_offset)
        return rawreg.get_root(h)

    def render_text(self, outfd, data):
        outfd.write("{0:20s} {1}\n".format("Last Written", "Key"))
        self.print_key(outfd, '', data)

    def print_key(self, outfd, keypath, key):
        if key.Name != None:
            outfd.write("{0:20s} {1}\n".format(key.LastWriteTime, keypath + "\\" + key.Name))
        for k in rawreg.subkeys(key):
            self.print_key(outfd, keypath + "\\" + key.Name, k)
