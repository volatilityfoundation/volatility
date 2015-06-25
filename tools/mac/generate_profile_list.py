# Volatility
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

'''
This helper script generates (kernel version, version address pairs)
to help generate the list used by mac_get_profiles

Run it from the Mac directory of the Volatility profiles repo
'''

import os, sys, re
import zipfile

def parse_dsymutil(data, module):
    """Parse the symbol file."""
    sys_map = {}
    sys_map[module] = {}

    want_lower = ["_IdlePML4"]        

    type_map = {}
    type_map[module] = {}

    # get the system map
    for line in data.splitlines():
        ents = line.split()

        match = re.search("\[.*?\(([^\)]+)\)\s+[0-9A-Fa-z]+\s+\d+\s+([0-9A-Fa-f]+)\s'(\w+)'", line)

        if match:
            (sym_type, addr, name) = match.groups()
            sym_type = sym_type.strip()
    
            addr = int(addr, 16)

            if addr == 0 or name == "":
                continue

            if not name in sys_map[module]:
                sys_map[module][name] = [(addr, sym_type)]
                
            # every symbol is in the symbol table twice
            # except for the entries in 'want_lower', we need the higher address for all 
            oldaddr = sys_map[module][name][0][0]
            if addr < oldaddr and name in want_lower:
                sys_map[module][name] = [(addr, sym_type)]
        
            if not addr in type_map[module]:
                type_map[module][addr] = (name, [sym_type])

            type_map[module][addr][1].append(sym_type)

    return sys_map["kernel"]

print "profiles = ["

for path in set("."):
    for path, _, files in os.walk(path):
        for fn in files:
            if zipfile.is_zipfile(os.path.join(path, fn)):
                profpkg = zipfile.ZipFile(os.path.join(path, fn))

                for f in profpkg.filelist:
                    if 'symbol.dsymutil' in f.filename.lower():
                        data = parse_dsymutil(profpkg.read(f.filename), "kernel")
           
                        if "_lowGlo" in data:
                            lg = data["_lowGlo"][0][0]
                        else:
                            lg = "0"

                        if "_BootPML4" in data:
                            aslr = 1
                        else:
                            aslr = 0

                        name = fn.replace(".zip", "")
                        name = 'Mac' + name.replace('.', '_')

                        if name.find("Intel") == -1:
                            name = name + "x64"
                        else:
                            name = name + "x86"

                        print "[\"%s\", %s, %s, %d]," % (name, data["_version"][0][0], lg, aslr)

print "]"

