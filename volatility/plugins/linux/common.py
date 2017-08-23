# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""
import os, re

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
    if obj_ref._config.SHIFT:
        debug.error("Linux uses --virtual_shift and --physical_shift. Please run linux_aslr_shift to obtain the values.")

    obj_ref.addr_space = utils.load_as(obj_ref._config)

    if not obj_ref.is_valid_profile(obj_ref.addr_space.profile):
        debug.error("This command does not support the selected profile.")

class AbstractLinuxCommand(commands.Command):
    def __init__(self, *args, **kwargs):
        self.addr_space = None
        self.known_addrs = {}
        self.known_fops  = {}
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

    @staticmethod
    def register_options(config):
        config.add_option("PHYSICAL_SHIFT", type = 'int', default = 0, help = "Linux kernel physical shift address")
        config.add_option("VIRTUAL_SHIFT", type = 'int', default = 0, help = "Linux kernel virtual shift address")

    def is_known_address(self, addr, modules):
        addr = int(addr)

        text = self.profile.get_symbol("_text")
        etext = self.profile.get_symbol("_etext")

        return (self.addr_space.address_compare(addr, text) != -1 and self.addr_space.address_compare(addr, etext) == -1) or self.address_in_module(addr, modules)

    def address_in_module(self, addr, modules):
    
        for (_, start, end) in modules:
            if self.addr_space.address_compare(addr, start) != -1 and self.addr_space.address_compare(addr, end) == -1:
                return True
    
        return False

    def verify_ops(self, ops, op_members, modules):
        ops_addr = ops.v()        
        ops_list = []

        if ops_addr in self.known_fops:
            for check, addr in self.known_fops[ops_addr]:
                yield check, addr

            return

        for check in op_members:
            addr = int(ops.m(check))

            if addr and addr != 0 and addr != -1:
                if addr in self.known_addrs:
                    known = self.known_addrs[addr]
                else:
                    known = self.is_known_address(addr, modules)
                    self.known_addrs[addr] = known
                
                if known == 0:
                    yield (check, addr)
                    ops_list.append((check, addr))

        self.known_fops[ops_addr] = ops_list

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

def _get_path_file(task, filp):
    rdentry = task.fs.get_root_dentry()
    rmnt    = task.fs.get_root_mnt()
    dentry  = filp.dentry
    vfsmnt  = filp.vfsmnt
    
    return do_get_path(rdentry, rmnt, dentry, vfsmnt)

def get_new_sock_pipe_path(task, filp):
    dentry = filp.dentry

    sym = dentry.obj_vm.profile.get_symbol_by_address("kernel", dentry.d_op.d_dname)
    
    if sym:
        if sym == "sockfs_dname":
            pre_name = "socket"    
    
        elif sym == "anon_inodefs_dname":
            pre_name = "anon_inode"

        elif sym == "pipefs_dname":
            pre_name = "pipe"

        elif sym == "simple_dname":
            pre_name = _get_path_file(task, filp)

        else:
            print "no handler for %s" % sym
            pre_name = "<BAD>"

        ret = "%s:[%d]" % (pre_name, dentry.d_inode.i_ino)

    else:
        ret = "<BAD d_dname pointer>"

    return ret

def get_path(task, filp):
    dentry = filp.dentry

    if dentry.d_op and hasattr(dentry.d_op, "d_dname") and dentry.d_op.d_dname:
        ret = get_new_sock_pipe_path(task, filp)
    else:
        ret = _get_path_file(task, filp)

    return ret

def write_elf_file(dump_dir, task, elf_addr):
    file_name = re.sub("[./\\\]", "", str(task.comm))

    file_path = os.path.join(dump_dir, "%s.%d.%#8x" % (file_name, task.pid, elf_addr))

    file_contents = task.get_elf(elf_addr)

    fd = open(file_path, "wb")
    fd.write(file_contents)
    fd.close()       

    return file_path 

def get_time_vars(obj_vm):
    '''
    Sometime in 3.[3-5], Linux switched to a global timekeeper structure
    This just figures out which is in use and returns the correct variables
    '''
    wall_addr       = obj_vm.profile.get_symbol("wall_to_monotonic")
    sleep_addr      = obj_vm.profile.get_symbol("total_sleep_time")
    timekeeper_addr = obj_vm.profile.get_symbol("timekeeper")
    tkcore_addr     = obj_vm.profile.get_symbol("tk_core") 

    wall  = None
    timeo = None

    # old way
    if wall_addr and sleep_addr:
        wall = obj.Object("timespec", offset = wall_addr, vm = obj_vm)
        timeo = obj.Object("timespec", offset = sleep_addr, vm = obj_vm)

    elif wall_addr:
        wall  = obj.Object("timespec", offset = wall_addr, vm = obj_vm)
        timeo = vol_timespec(0, 0)

    # timekeeper way
    elif timekeeper_addr:
        timekeeper = obj.Object("timekeeper", offset = timekeeper_addr, vm = obj_vm)
        wall = timekeeper.wall_to_monotonic
        timeo = timekeeper.total_sleep_time

    # 3.17(ish) - 3.19(ish) way
    elif tkcore_addr and hasattr("timekeeper", "total_sleep_time"):
        # skip seqcount
        timekeeper = obj.Object("timekeeper", offset = tkcore_addr + 4, vm = obj_vm)
        wall = timekeeper.wall_to_monotonic
        timeo = timekeeper.total_sleep_time

    # 3.19(ish)+
    # getboottime from 3.19.x
    elif tkcore_addr:
        # skip seqcount
        timekeeper = obj.Object("timekeeper", offset = tkcore_addr + 8, vm = obj_vm)
        wall = timekeeper.wall_to_monotonic

        oreal = timekeeper.offs_real
        oboot = timekeeper.offs_boot

        if hasattr(oreal,"tv64"):
            tv64 = (oreal.tv64 & 0xffffffff) - (oboot.tv64 & 0xffffffff)
        else:
            tv64 = (oreal & 0xffffffff) - (oboot & 0xffffffff)
            
        if tv64:
            tv64 = (tv64 / 100000000) * -1
            timeo = vol_timespec(tv64, 0) 
        else:
            timeo = None

    return (wall, timeo)

