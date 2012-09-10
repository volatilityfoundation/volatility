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

import time
nsecs_per = 1000000000

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

    def get_profile_symbol(self, sym_name, nm_type = "", sym_type = "", module = "kernel"):
        '''
        Gets a symbol out of the profile
        syn_name -> name of the symbol
        nm_tyes  -> types as defined by 'nm' (man nm for examples)
        sym_type -> the type of the symbol (passing Pointer will provide auto deref)
        module   -> which module to get the symbol from, default is kernel, otherwise can be any name seen in 'lsmod'

        Just a wrapper for AbstractLinuxProfile.get_symbol
        '''
        return self.profile.get_symbol(sym_name, nm_type, sym_type, module)

    # In 2.6.3x, Linux changed how the symbols for per_cpu variables were named
    # This handles both formats so plugins needing per-cpu vars are cleaner
    def get_per_cpu_symbol(self, sym_name, module = "kernel"):

        ret = self.get_profile_symbol(sym_name, module = module)

        if not ret:
            ret = self.get_profile_symbol("per_cpu__" + sym_name, module = module)

        return ret

    ## FIXME: This currently returns using localtime, we should probably use UTC?
    def get_task_start_time(self, task):

        start_time = task.start_time

        start_secs = start_time.tv_sec + (start_time.tv_nsec / nsecs_per / 100)

        sec = self.get_boot_time() + start_secs

        # protect against invalid data in unallocated tasks
        try:
            ret = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(sec))
        except ValueError:
            ret = ""

        return ret

    # returns a list of online cpus (the processor numbers)
    def online_cpus(self):
        cpu_online_bits_addr = self.get_profile_symbol("cpu_online_bits")
        cpu_present_map_addr = self.get_profile_symbol("cpu_present_map")

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

        offset_var = self.get_profile_symbol("__per_cpu_offset")
        per_offsets = obj.Object(theType = 'Array', targetType = 'unsigned long', count = max_cpu, offset = offset_var, vm = self.addr_space)

        for i in range(max_cpu):

            offset = per_offsets[i]

            cpu_var = self.get_per_cpu_symbol(per_var)

            addr = cpu_var + offset.v()
            var = obj.Object(var_type, offset = addr, vm = self.addr_space)

            yield i, var

    def get_time_vars(self):
        '''
        Sometime in 3.[3-5], Linux switched to a global timekeeper structure
        This just figures out which is in use and returns the correct variables
        '''

        wall_addr = self.get_profile_symbol("wall_to_monotonic")

        # old way
        if wall_addr:
            wall = obj.Object("timespec", offset = wall_addr, vm = self.addr_space)

            sleep_addr = self.get_profile_symbol("total_sleep_time")
            timeo = obj.Object("timespec", offset = sleep_addr, vm = self.addr_space)

        # timekeeper way
        else:
            timekeeper_addr = self.get_profile_symbol("timekeeper")

            timekeeper = obj.Object("timekeeper", offset = timekeeper_addr, vm = self.addr_space)

            wall = timekeeper.wall_to_monotonic
            timeo = timekeeper.total_sleep_time

        return (wall, timeo)

    # based on 2.6.35 getboottime
    def get_boot_time(self):

        (wall, timeo) = self.get_time_vars()

        secs = wall.tv_sec + timeo.tv_sec
        nsecs = wall.tv_nsec + timeo.tv_nsec

        secs = secs * -1
        nsecs = nsecs * -1

        while nsecs >= nsecs_per:

            nsecs = nsecs - nsecs_per

            secs = secs + 1

        while nsecs < 0:

            nsecs = nsecs + nsecs_per

            secs = secs - 1

        boot_time = secs + (nsecs / nsecs_per / 100)

        return boot_time

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

###################
# code to walk the page cache and mem_map / mem_section page structs
###################
def radix_tree_is_indirect_ptr(self, ptr):

    return ptr & 1

def radix_tree_indirect_to_ptr(self, ptr):

    return obj.Object("radix_tree_node", offset = ptr & ~1, vm = self.addr_space)

def radix_tree_lookup_slot(self, root, index):

    self.RADIX_TREE_MAP_SHIFT = 6
    self.RADIX_TREE_MAP_SIZE = 1 << self.RADIX_TREE_MAP_SHIFT
    self.RADIX_TREE_MAP_MASK = self.RADIX_TREE_MAP_SIZE - 1

    node = root.rnode

    if radix_tree_is_indirect_ptr(self, node) == 0:

        if index > 0:
            #print "returning None: index > 0"
            return None

        #print "returning obj_Offset"
        off = root.obj_offset + self.profile.get_obj_offset("radix_tree_root", "rnode")

        page = obj.Object("Pointer", offset = off, vm = self.addr_space)

        return page

    node = radix_tree_indirect_to_ptr(self, node)

    height = node.height

    shift = (height - 1) * self.RADIX_TREE_MAP_SHIFT

    slot = -1

    while 1:

        idx = (index >> shift) & self.RADIX_TREE_MAP_MASK

        slot = node.slots[idx]

        shift = shift - self.RADIX_TREE_MAP_SHIFT

        height = height - 1

        if height <= 0:
            break

    if slot == -1:
        return None

    return slot

def SHMEM_I(self, inode):

    offset = self.profile.get_obj_offset("shmem_inode_info", "vfs_inode")

    return obj.Object("shmem_inode_info", offset = inode.obj_offset - offset, vm = self.addr_space)

def find_get_page(self, inode, offset):

    page = radix_tree_lookup_slot(self, inode.i_mapping.page_tree, offset)

    #if not page:
        # FUTURE swapper_space support
        #print "no page"

    return page

def get_page_contents(self, inode, idx):
    page_addr = find_get_page(self, inode, idx)

    if page_addr:
        page = obj.Object("page", offset = page_addr, vm = self.addr_space)

        phys_offset = page.to_paddr()

        phys_as = utils.load_as(self._config, astype = 'physical')

        data = phys_as.zread(phys_offset, 4096)
    else:
        data = "\x00" * 4096

    return data

# main function to be called, handles getting all the pages of an inode
# and handles the last page not being page_size aligned 
def get_file_contents(self, inode):

    data = ""
    file_size = inode.i_size

    extra = file_size % 4096

    idxs = file_size / 4096

    if extra != 0:
        extra = 4096 - extra
        idxs = idxs + 1

    for idx in range(0, idxs):

        data = data + get_page_contents(self, inode, idx)

    # this is chop off any extra data on the last page

    if extra != 0:
        extra = extra * -1

        data = data[:extra]

    return data

# This returns the name of the module that contains an address or None
# The module_list parameter comes from a call to get_modules
# This function will be updated after 2.2 to resolve symbols within the module as well
def address_in_module(module_list, address):
    ret = None

    for (name, start, end) in module_list:

        if start <= address < end:

            ret = name
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


