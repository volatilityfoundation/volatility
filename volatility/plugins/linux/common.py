# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.commands as commands
import volatility.utils as utils
import volatility.debug as debug
import volatility.obj as obj

MAX_STRING_LENGTH = 256

nsecs_per = 1000000000

class vol_timespec:

    def __init__(self, secs, nsecs):
        self.tv_sec  = secs
        self.tv_nsec = nsecs

def set_plugin_members(obj_ref):
    obj_ref.addr_space = utils.load_as(obj_ref._config)

    if not obj_ref.is_valid_profile(obj_ref.addr_space.profile):
        debug.error("This command does not support the selected profile.")

class AbstractLinuxCommand(commands.Command):
    def __init__(self, *args, **kwargs):
        self.addr_space = None
        self.known_addrs = {}
        commands.Command.__init__(self, *args, **kwargs)

    @property
    def profile(self):
        if self.addr_space:
            return self.addr_space.profile
        return None

    def execute(self, *args, **kwargs):
        commands.Command.execute(self, *args, **kwargs)

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'linux'

    def is_known_address(self, addr, modules):

        text = self.profile.get_symbol("_text")
        etext = self.profile.get_symbol("_etext")

        return (self.addr_space.address_compare(addr, text) != -1 and self.addr_space.address_compare(addr, etext) == -1) or self.address_in_module(addr, modules)

    def address_in_module(self, addr, modules):
    
        for (_, start, end) in modules:
            if self.addr_space.address_compare(addr, start) != -1 and self.addr_space.address_compare(addr, end) == -1:
                return True
    
        return False

    def verify_ops(self, ops, op_members, modules):

        for check in op_members:
            addr = ops.m(check)

            if addr and addr != 0:

                if addr in self.known_addrs:
                    known = self.known_addrs[addr]
                else:
                    known = self.is_known_address(addr, modules)
                    self.known_addrs[addr] = known
                
                if known == 0:
                    yield (check, addr)

class AbstractLinuxIntelCommand(AbstractLinuxCommand):
    @staticmethod
    def is_valid_profile(profile):
        return AbstractLinuxCommand.is_valid_profile(profile) \
        and (profile.metadata.get('arch').lower() == 'x86' \
        or profile.metadata.get('arch').lower() == 'x64')

class AbstractLinuxARMCommand(AbstractLinuxCommand):
    @staticmethod
    def is_valid_profile(profile):
        return AbstractLinuxCommand.is_valid_profile(profile) \
        and (profile.metadata.get('arch').lower() == 'arm')                   
 
def walk_internal_list(struct_name, list_member, list_start, addr_space = None):
    if not addr_space:
        addr_space = list_start.obj_vm

    while list_start:
        list_struct = obj.Object(struct_name, vm = addr_space, offset = list_start.v())
        yield list_struct
        list_start = getattr(list_struct, list_member)

# based on __d_path
def do_get_path(rdentry, rmnt, dentry, vfsmnt):
    ret_path = []

    inode = dentry.d_inode

    if not rdentry.is_valid() or not dentry.is_valid():
        return []

    while (dentry != rdentry or vfsmnt != rmnt) and dentry.d_name.name.is_valid():

        dname = dentry.d_name.name.dereference_as("String", length = MAX_STRING_LENGTH)

        ret_path.append(dname.strip('/'))

        if dentry == vfsmnt.mnt_root or dentry == dentry.d_parent:
            if vfsmnt.mnt_parent == vfsmnt.v():
                break
            dentry = vfsmnt.mnt_mountpoint
            vfsmnt = vfsmnt.mnt_parent
            continue

        parent = dentry.d_parent
        dentry = parent

    ret_path.reverse()

    if ret_path == []:
        return []

    ret_val = '/'.join([str(p) for p in ret_path if p != ""])

    if ret_val.startswith(("socket:", "pipe:")):
        if ret_val.find("]") == -1:
            ret_val = ret_val[:-1] + ":[{0}]".format(inode.i_ino)
        else:
            ret_val = ret_val.replace("/", "")

    elif ret_val != "inotify":
        ret_val = '/' + ret_val

    return ret_val

def get_path(task, filp):
    rdentry = task.fs.get_root_dentry()
    rmnt = task.fs.get_root_mnt()
    dentry = filp.dentry
    vfsmnt = filp.vfsmnt

    return do_get_path(rdentry, rmnt, dentry, vfsmnt)

