# Volatility
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.commands as commands
import volatility.utils as utils
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.linux.flags as linux_flags

MAX_STRING_LENGTH = 256

nsecs_per = 1000000000

class vol_timespec:

    def __init__(self, secs, nsecs):
        self.tv_sec  = secs
        self.tv_nsec = nsecs

def set_plugin_members(obj_ref):
    obj_ref.addr_space = utils.load_as(obj_ref._config)

class AbstractLinuxCommand(commands.Command):
    def __init__(self, *args, **kwargs):
        self.addr_space = None
        self.known_addrs = []
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

    # In 2.6.3x, Linux changed how the symbols for per_cpu variables were named
    # This handles both formats so plugins needing per-cpu vars are cleaner
    def get_per_cpu_symbol(self, sym_name, module = "kernel"):

        ret = self.addr_space.profile.get_symbol(sym_name, module = module)

        if not ret:
            ret = self.addr_space.profile.get_symbol("per_cpu__" + sym_name, module = module)

        return ret

    # returns a list of online cpus (the processor numbers)
    def online_cpus(self):
        cpu_online_bits_addr = self.addr_space.profile.get_symbol("cpu_online_bits")
        cpu_present_map_addr = self.addr_space.profile.get_symbol("cpu_present_map")

        #later kernels..
        if cpu_online_bits_addr:
            bmap = obj.Object("unsigned long", offset = cpu_online_bits_addr, vm = self.addr_space)

        elif cpu_present_map_addr:
            bmap = obj.Object("unsigned long", offset = cpu_present_map_addr, vm = self.addr_space)

        else:
            raise AttributeError, "Unable to determine number of online CPUs for memory capture"

        cpus = []
        for i in range(8):
            if bmap & (1 << i):
                cpus.append(i)

        return cpus

    def walk_per_cpu_var(self, per_var, var_type):

        cpus = self.online_cpus()

        # get the highest numbered cpu
        max_cpu = cpus[-1] + 1

        offset_var = self.addr_space.profile.get_symbol("__per_cpu_offset")
        per_offsets = obj.Object(theType = 'Array', targetType = 'unsigned long', count = max_cpu, offset = offset_var, vm = self.addr_space)

        for i in range(max_cpu):

            offset = per_offsets[i]

            cpu_var = self.get_per_cpu_symbol(per_var)

            addr = cpu_var + offset.v()
            var = obj.Object(var_type, offset = addr, vm = self.addr_space)

            yield i, var

    def is_known_address(self, addr, modules):

        text = self.profile.get_symbol("_text", sym_type = "Pointer")
        etext = self.profile.get_symbol("_etext", sym_type = "Pointer")

        return  (text <= addr < etext or address_in_module(modules, addr))

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

# similar to for_each_process for this usage
def walk_list_head(struct_name, list_member, list_head_ptr, _addr_space):
    debug.warning("Deprecated use of walk_list_head")

    for item in list_head_ptr.list_of_type(struct_name, list_member):
        yield item

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

def S_ISDIR(mode):
    return (mode & linux_flags.S_IFMT) == linux_flags.S_IFDIR

def S_ISREG(mode):
    return (mode & linux_flags.S_IFMT) == linux_flags.S_IFREG

# This returns the name of the module that contains an address or None
# The module_list parameter comes from a call to get_modules
# This function will be updated after 2.2 to resolve symbols within the module as well
def address_in_module(module_list, address):
    ret = False

    for (name, start, end) in module_list:

        if start <= address < end:

            ret = True
            break

    return ret

# we can't get the full path b/c we 
# do not have a ref to the vfsmnt
def get_partial_path(dentry):
    path = []

    name = ""

    while dentry and dentry != dentry.d_parent:
        name = dentry.d_name.name.dereference_as("String", length = 255)
        if name.is_valid():
            path.append(str(name))
        dentry = dentry.d_parent

    path.reverse()

    str_path = "/".join([p for p in path])

    return str_path


