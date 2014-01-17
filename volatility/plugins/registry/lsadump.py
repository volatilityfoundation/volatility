# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

import volatility.win32.lsasecrets as lsasecrets
import volatility.win32.hashdump as hashdumpmod
import volatility.debug as debug
import volatility.cache as cache
import volatility.utils as utils
import volatility.plugins.common as common

class LSADump(common.AbstractWindowsCommand):
    """Dump (decrypted) LSA secrets from the registry"""
    # Declare meta information associated with this plugin

    meta_info = {}
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
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

class HashDump(common.AbstractWindowsCommand):
    """Dumps passwords hashes (LM/NTLM) from memory"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
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
                debug.debug("Unable to read hashes from registry")
            else:
                outfd.write(d + "\n")
