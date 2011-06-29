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

# from volatility.win32.datetime import windows_to_unix_time
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.debug as debug
import volatility.utils as utils
import volatility.commands as commands
import volatility.plugins.registry.hivelist as hivelist

## This module requires a filename to be passed by the user
#config.add_option("HIVE-OFFSET", default = 0, type='int',
#                  help = "Offset to reg hive")

def vol(k):
    return bool(k.obj_offset & 0x80000000)

FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])

def hd(src, length = 16):
    N = 0
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["{0:02X}".format(ord(k)) for k in s])
        s = s.translate(FILTER)
        result += "{0:04X}   {2:{1}}   {3}\n".format(N, length * 3, hexa, s)
        N += length
    return result

class PrintKey(hivelist.HiveList):
    "Print a registry key, and its subkeys and values"
    # Declare meta information associated with this plugin

    meta_info = commands.command.meta_info
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def __init__(self, config, *args):
        hivelist.HiveList.__init__(self, config, *args)
        config.add_option('HIVE-OFFSET', short_option = 'o',
                          help = 'Hive offset (virtual)', type = 'int')
        config.add_option('KEY', short_option = 'K',
                          help = 'Registry Key', type = 'str')

    def hive_name(self, hive):
        try:
            return hive.FileFullPath.v() or hive.FileUserName.v() or hive.HiveRootPath.v() or "[no name]"
        except AttributeError:
            return "[no name]"

    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self._config.HIVE_OFFSET:
            hive_offsets = [(self.hive_name(h), h.obj_offset) for h in hivelist.HiveList.calculate(self)]
        else:
            hive_offsets = [("User Specified", self._config.HIVE_OFFSET)]

        for name, hoff in set(hive_offsets):
            h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)
            root = rawreg.get_root(h)
            if not root:
                if self._config.HIVE_OFFSET:
                    debug.error("Unable to find root key. Is the hive offset correct?")
            else:
                if self._config.KEY:
                    yield name, rawreg.open_key(root, self._config.KEY.split('\\'))
                else:
                    yield name, root

    def voltext(self, key):
        return "(V)" if vol(key) else "(S)"

    def render_text(self, outfd, data):
        outfd.write("Legend: (S) = Stable   (V) = Volatile\n\n")
        keyfound = False
        for reg, key in data:
            if key:
                keyfound = True
                outfd.write("----------------------------\n")
                outfd.write("Registry: {0}\n".format(reg))
                outfd.write("Key name: {0} {1:3s}\n".format(key.Name, self.voltext(key)))
                outfd.write("Last updated: {0}\n".format(key.LastWriteTime))
                outfd.write("\n")
                outfd.write("Subkeys:\n")
                for s in rawreg.subkeys(key):
                    if s.Name == None:
                        outfd.write("  Unknown subkey: " + s.Name.reason + "\n")
                    else:
                        outfd.write("  {1:3s} {0}\n".format(s.Name, self.voltext(s)))
                outfd.write("\n")
                outfd.write("Values:\n")
                for v in rawreg.values(key):
                    tp, dat = rawreg.value_data(v)
                    if tp == 'REG_BINARY':
                        dat = "\n" + hd(dat, length = 16)
                    if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                        dat = dat.encode("ascii", 'backslashreplace')
                    if tp == 'REG_MULTI_SZ':
                        for i in range(len(dat)):
                            dat[i] = dat[i].encode("ascii", 'backslashreplace')
                    outfd.write("{0:13} {1:15} : {3:3s} {2}\n".format(tp, v.Name, dat, self.voltext(v)))
        if not keyfound:
            outfd.write("The requested key could not be found in the hive(s) searched\n")
