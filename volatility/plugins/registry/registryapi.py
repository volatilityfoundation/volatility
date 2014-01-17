# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie.levy@gmail.com>
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
@author:       Jamie Levy (Gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie.levy@gmail.com
@organization: Volatility Foundation
"""

import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.win32.hashdump as hashdump
import volatility.utils as utils
import volatility.plugins.registry.hivelist as hl
from heapq import nlargest


class RegistryApi(object):
    """A wrapper several highly used Registry functions"""

    def __init__(self, config):
        self._config = config
        self.addr_space = utils.load_as(self._config)
        self.all_offsets = {}
        self.current_offsets = {}
        self.populate_offsets()

    def print_offsets(self):
        '''
        this is just in case we want to check our offsets and which hive(s) was/were chosen
        '''
        for item in self.all_offsets:
            print "0x{0:x}".format(item), self.all_offsets[item]
        for item in self.current_offsets:
            print 'current', "0x{0:x}".format(item), self.current_offsets[item]

    def populate_offsets(self):
        '''
        get all hive offsets so we don't have to scan again...
        '''
        hive_offsets = []
        hiveroot = hl.HiveList(self._config).calculate()

        for hive in hiveroot:
            if hive.obj_offset not in hive_offsets:
                hive_offsets.append(hive.obj_offset)
                try:
                    name = hive.FileFullPath.v() or hive.FileUserName.v() or hive.HiveRootPath.v() or "[no name]"
                # What exception are we expecting here?
                except:
                    name = "[no name]"
                self.all_offsets[hive.obj_offset] = name

    def reg_get_currentcontrolset(self, fullname = True):
        '''
        get the CurrentControlSet
            If fullname is not specified, we only get the number like "1" or "2" etc
            The default is ControlSet00{#} so we can append it to the desired key path
            We return None if it fails, so you need to verify before using.
        '''
        for offset in self.all_offsets:
            name = self.all_offsets[offset] + " "
            if name.lower().find("\\system ") != -1:
                sysaddr = hivemod.HiveAddressSpace(self.addr_space, self._config, offset)
                if fullname:
                    return "ControlSet00{0}".format(hashdump.find_control_set(sysaddr))
                else:
                    return hashdump.find_control_set(sysaddr)
        return None

    def set_current(self, hive_name = None, user = None):
        '''
        if we find a hive that fits the given criteria, save its offset 
        so we don't have to scan again.  this can be reset using reset_current
        if context changes
        '''
        for item in self.all_offsets:
            name = self.all_offsets[item] + " "
            if user == None and hive_name == None:
                #no particular preference: all hives
                self.current_offsets[item] = name
            elif user != None and name.lower().find('\\' + user.lower() + '\\') != -1 and name.lower().find("\\" + "ntuser.dat ") != -1:
                #user's NTUSER.DAT hive
                self.current_offsets[item] = name
            elif hive_name != None and hive_name.lower() == 'hklm' \
                and (name.lower().find("\\security ") != -1 or name.lower().find("\\system ") != -1 \
                or name.lower().find("\\software ") != -1 or name.lower().find("\\sam ") != -1):
                #any HKLM hive 
                self.current_offsets[item] = name
            elif hive_name != None and name.lower().find("\\" + hive_name.lower() + " ") != -1 and user == None:
                #a particular hive indicated by hive_name
                if hive_name.lower() == "system" and name.lower().find("\\syscache.hve ") == -1:
                    self.current_offsets[item] = name
                elif hive_name.lower() != "system":
                    self.current_offsets[item] = name

    def reset_current(self):
        '''
        this is in case we switch to a different hive/user/context
        '''
        self.current_offsets = {}

    def reg_get_key(self, hive_name, key, user = None, given_root = None):
        '''
        Returns a key from a requested hive; assumes this is from a single hive
        if more than one hive is specified, the hive/key found is returned
        '''
        if self.all_offsets == {}:
            self.populate_offsets()
        if self.current_offsets == {}:
            self.set_current(hive_name, user)
        if key:
            for offset in self.current_offsets:
                if given_root == None:
                    h = hivemod.HiveAddressSpace(self.addr_space, self._config, offset)
                    root = rawreg.get_root(h)
                else:
                    root = given_root
                if root != None:
                    k = rawreg.open_key(root, key.split('\\'))
                    if k:
                        return k
        return None

    def reg_yield_key(self, hive_name, key, user = None, given_root = None):
        ''' 
        Use this function if you are collecting keys from more than one hive
        '''
        if self.all_offsets == {}:
            self.populate_offsets()
        if self.current_offsets == {}:
            self.set_current(hive_name, user)
        if key:
            for offset in self.current_offsets:
                name = self.current_offsets[offset]
                if given_root == None:
                    h = hivemod.HiveAddressSpace(self.addr_space, self._config, offset)
                    root = rawreg.get_root(h)
                else:
                    root = given_root
                if root != None:
                    k = rawreg.open_key(root, key.split('\\'))
                    if k:
                        yield k, name

    def reg_enum_key(self, hive_name, key, user = None):
        '''
        This function enumerates the requested key
        '''
        k = self.reg_get_key(hive_name, key, user)
        if k:
            for s in rawreg.subkeys(k):
                if s.Name:
                    item = key + '\\' + s.Name
                    yield item

    def reg_get_all_subkeys(self, hive_name, key, user = None, given_root = None):
        '''
        This function enumerates the subkeys of the requested key
        '''
        k = given_root if given_root != None else self.reg_get_key(hive_name, key)
        if k:
            for s in rawreg.subkeys(k):
                if s.Name:
                    yield s

    def reg_yield_values(self, hive_name, key, thetype = None, given_root = None):
        '''
        This function yields all values for a  requested registry key
        '''
        if key:
            h = given_root if given_root != None else self.reg_get_key(hive_name, key)
            if h != None:
                for v in rawreg.values(h):
                    tp, dat = rawreg.value_data(v)
                    if thetype == None or tp == thetype:
                        yield v.Name, dat 

    def reg_get_value(self, hive_name, key, value, strcmp = None, given_root = None):
        '''
        This function returns the requested value of a registry key
        '''
        if key and value:
            h = given_root if given_root != None else self.reg_get_key(hive_name, key)
            if h != None:
                for v in rawreg.values(h):
                    if value == v.Name:
                        tp, dat = rawreg.value_data(v)
                        if tp == 'REG_BINARY' or strcmp == None:
                            # We want raw data
                            return dat
                        else:
                            # This is a string comparison
                            dat = str(dat)
                            dat = dat.strip()
                            dat = ''.join([x for x in dat if ord(x) != 0])  #get rid of funky nulls for string comparison
                            if strcmp == dat:
                                return dat
        return None

    def reg_get_all_keys(self, hive_name, user = None, start = None, end = None, reg = False, rawtime = False):
        '''
        This function enumerates all keys in specified hives and 
        collects lastwrite times.
        '''
        keys = []
        if self.all_offsets == {}:
            self.populate_offsets()
        if self.current_offsets == {}:
            self.set_current(hive_name, user)

        # Collect the root keys 
        for offset in self.current_offsets:
            reg_name = self.current_offsets[offset]
            h = hivemod.HiveAddressSpace(self.addr_space, self._config, offset)
            root = rawreg.get_root(h)
            if not root:
                pass
            else:
                time = "{0}".format(root.LastWriteTime) if not rawtime else root.LastWriteTime
                if reg:
                    if start and end and str(time) >= start and str(time) <= end:
                        yield (time, reg_name, root.Name)
                    elif start == None and end == None:
                        yield (time, reg_name, root.Name)
                else:
                    if start and end and str(time) >= start and str(time) <= end:
                        yield (time, root.Name)
                    elif start == None and end == None:
                        yield (time, root.Name)
                for s in rawreg.subkeys(root):
                    if reg:
                        keys.append([s, reg_name, root.Name + "\\" + s.Name])
                    else:
                        keys.append([s, root.Name + "\\" + s.Name])

        # Get subkeys
        if reg:
            for k, reg_name, name in keys:
                time = "{0}".format(k.LastWriteTime) if not rawtime else k.LastWriteTime
                if start and end and str(time) >= start and str(time) <= end:
                    yield (time, reg_name, name)
                elif start == None and end == None:
                    yield (time, reg_name, name)
                for s in rawreg.subkeys(k):
                    if name and s.Name:
                        item = name + '\\' + s.Name
                        keys.append([s, reg_name, item])
        else:
            for k, name in keys:
                time = "{0}".format(k.LastWriteTime) if not rawtime else k.LastWriteTime
                if start and end and str(time) >= start and str(time) <= end:
                    yield (time, name)
                elif start == None and end == None:
                    yield (time, name)

                for s in rawreg.subkeys(k):
                    if name and s.Name:
                        item = name + '\\' + s.Name
                        keys.append([s, item])

    def reg_get_last_modified(self, hive_name, count = 1, user = None, start = None, end = None, reg = False):
        '''
        Wrapper function using reg_get_all_keys. These functions can take a WHILE since all 
        subkeys have to be collected before you can compare lastwrite times.
        '''
        data = nlargest(count, self.reg_get_all_keys(hive_name, user, start, end, reg))
        if reg:
            for t, regname, name in data:
                yield (t, regname, name)
        else:
            for t, name in data: 
                yield (t, name)


