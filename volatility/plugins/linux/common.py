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

# FIXME
# get rid of this! used by lsof
def mask_number(num):
    return num & 0xffffffff

class AbstractLinuxCommand(commands.Command):

    def __init__(self, *args, **kwargs):
        self.addr_space = None
        commands.Command.__init__(self, *args, **kwargs)

    @property
    def profile(self):
        if self.addr_space:
            return self.addr_space.profile
        return None

    def execute(self, *args, **kwargs):
        self.addr_space = utils.load_as(self._config)
        commands.Command.execute(self, *args, **kwargs)

        # this was the old method to get data from system.map, do not use anymore, use get_symbol below instead
        # self.smap       = self.profile.sysmap

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'linux'

    '''
    Gets a symbol out of the profile
    syn_name -> name of the symbol
    nm_tyes  -> types as defined by 'nm' (man nm for examples)
    sym_type -> the type of the symbol (passing Pointer will provide auto deref)
    module   -> which module to get the symbol from, default is kernel, otherwise can be any name seen in 'lsmod'

    Just a wrapper for AbstractLinuxProfile.get_symbol
    '''
    def get_profile_symbol(self, sym_name, nm_type = "", sym_type = "", module = "kernel"):
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

        sec = get_boot_time(self) + start_secs

        return time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(sec))


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

def walk_per_cpu_var(obj_ref, per_var, var_type):

    cpus = online_cpus(obj_ref)

    # get the highest numbered cpu
    max_cpu = cpus[-1] + 1

    offset_var = obj_ref.get_profile_symbol("__per_cpu_offset")
    per_offsets = obj.Object(theType = 'Array', targetType = 'unsigned long', count = max_cpu, offset = offset_var, vm = obj_ref.addr_space)

    for i in range(max_cpu):

        offset = per_offsets[i]

        cpu_var = obj_ref.get_per_cpu_symbol(per_var)

        addr = cpu_var + offset.v()
        var = obj.Object(var_type, offset = addr, vm = obj_ref.addr_space)

        yield i, var

def get_time_vars(obj_ref):
    '''
    Sometime in 3.[3-5], Linux switched to a global timekeeper structure
    This just figures out which is in use and returns the correct variables
    '''

    wall_addr = obj_ref.get_profile_symbol("wall_to_monotonic")

    # old way
    if wall_addr:
        wall = obj.Object("timespec", offset = wall_addr, vm = obj_ref.addr_space)

        sleep_addr = obj_ref.get_profile_symbol("total_sleep_time")
        timeo = obj.Object("timespec", offset = sleep_addr, vm = obj_ref.addr_space)

    # timekeeper way
    else:
        timekeeper_addr = obj_ref.get_profile_symbol("timekeeper")

        timekeeper = obj.Object("timekeeper", offset = timekeeper_addr, vm = obj_ref.addr_space)

        wall = timekeeper.wall_to_monotonic
        timeo = timekeeper.total_sleep_time

    return (wall, timeo)

# based on 2.6.35 getboottime
def get_boot_time(obj_ref):

    (wall, timeo) = get_time_vars(obj_ref)

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
# TODO: (deleted) support
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

def get_obj(self, ptr, sname, member):

    offset = self.profile.get_obj_offset(sname, member)

    addr = ptr - offset

    return obj.Object(sname, offset = addr, vm = self.addr_space)

def S_ISDIR(mode):
    return (mode & linux_flags.S_IFMT) == linux_flags.S_IFDIR

def S_ISREG(mode):
    return (mode & linux_flags.S_IFMT) == linux_flags.S_IFREG

###################
# code to walk the page cache and mem_map / mem_section page structs
###################

'''
def SECTIONS_PER_ROOT(self, is_extreme):

    if is_extreme:
        secs_per_root = 4096 / self.profile.get_obj_size("mem_section")
    
    else:
        secs_per_root = 1

    return secs_per_root

def SECTION_NR_TO_ROOT(self, nr, is_extreme):

    secs_per_root = SECTIONS_PER_ROOT(self, is_extreme)

    return nr / secs_per_root

def SECTION_ROOT_MASK(self, is_extreme):

    return SECTIONS_PER_ROOT(self, is_extreme) - 1

def nr_to_section(self, secnum):

    # check if CONFIG_SPARSEMEM_EXTREME is set
    if "sparse_index_alloc" in self.smap:
       
        # mem_section is a double array of type 'mem_section'
 
        nr = SECTION_NR_TO_ROOT(self, secnum, 1)

        addr = self.smap["mem_section"]
        
        addr = addr + ( nr * self.profile.get_obj_size("mem_section") )

        # check the object here
        tmp = obj.Object("long", offset=addr, vm=self.addr_space)

        if not tmp.is_valid() or tmp in [None, 0]:
            return None

        #print "tmp: %x" % (tmp &  (2**64-1))

        offset = (nr & SECTION_ROOT_MASK(self, 1)) * self.profile.get_obj_size("mem_section")

        ret =  tmp + offset

        #print "extreme %s" % tohex(ret)

    else:
        
        off = SECTIONS_PER_ROOT(self, 0) * SECTION_NR_TO_ROOT(self, secnum, 0)
        ret = self.smap["mem_section"] + (off + (nr & SECTION_ROOT_MASK(self, 0)) * self.profile.get_obj_size("mem_section"))

    return ret
    
def read_mem_section(self, addr):
    
    if addr in [0, None]:
        return None

    testobj = obj.Object("mem_section", offset=addr, vm=self.addr_space)

    if testobj:
        SECTION_MAP_LAST_BIT = 1 << 2
        SECTION_MAP_MASK     = ~(SECTION_MAP_LAST_BIT-1)

        ret = testobj.section_mem_map & SECTION_MAP_MASK 
    else:
        ret = None
    
    return ret

def valid_section(self, addr):

    mem_section = read_mem_section(self, addr)

    return mem_section

def valid_section_nr(self, nr):

    addr = nr_to_section(self, nr);

    if valid_section(self, addr):
        ret = addr
    else:
        ret = 0 

    return ret

# FIXME 32 bit
# [SECTION_SIZE_BITS, MAX_PHYSADDR_BITS, MAX_PHYSMEM_BITS]
def get_bit_size(self):

    return [27, 44, 44]

def PFN_SECTION_SHIFT(self):

    # ?FIXME? arm
    return get_bit_size(self)[0] - 12

def section_nr_to_pfn(self, nr):

    return nr << PFN_SECTION_SHIFT(self)

def sparse_decode_mem_map(self, addr, nr):

    return addr + (section_nr_to_pfn(self, nr) * self.profile.get_obj_size("page"))

def section_mem_map_addr(self, addr):

    return read_mem_section(self, addr)

# most of the mem_section related work was based on crash
def get_phys_addr_section(self, page):

    (SECTION_SIZE_BITS, MAX_PHYSADDR_BITS, MAX_PHYSMEM_BITS) = get_bit_size(self)
    SECTIONS_SHIFT   = MAX_PHYSMEM_BITS - SECTION_SIZE_BITS
    
    num_sections = 1 << SECTIONS_SHIFT
    
    want_addr = page

    for secnum in range(0, num_sections):
    
        sec_addr = valid_section_nr(self, secnum) 
        
        if not sec_addr: 
            continue
    
        coded_mem_map = section_mem_map_addr(self, sec_addr)
    
        mem_map      = sparse_decode_mem_map(self, coded_mem_map, secnum)

        end_mem_map  = mem_map + ((1 << PFN_SECTION_SHIFT(self)) * self.profile.get_obj_size("page"))

        if mem_map <= want_addr < end_mem_map:

            section_paddr = section_nr_to_pfn(self, secnum) << 12

            pgnum = (want_addr - mem_map) / self.profile.get_obj_size("page")

            phys_offset = section_paddr + (pgnum * 4096)

            print "OFFSET: %d | %x || %s" % (phys_offset, phys_offset, tohex(coded_mem_map))
        
            return phys_offset


    debug.info("get_phys_addr_section: Unable to get address for page")
    return -1
'''

def phys_addr_of_page(self, page):

    mem_map_addr = self.get_profile_symbol("mem_map")
    mem_section_addr = self.get_profile_symbol("mem_section")

    if mem_map_addr:
        # FLATMEM kernels, usually 32 bit
        mem_map_ptr = obj.Object("Pointer", offset = mem_map_addr, vm = self.addr_space)

    elif mem_section_addr:
        # this is hardcoded in the kernel - VMEMMAPSTART, usually 64 bit kernels
        # NOTE: This is really 0xffff0xea0000000000 but we chop to its 48 bit equivalent
        # FIXME: change in 2.3 when truncation no longer occurs
        mem_map_ptr = 0xea0000000000

    else:
        debug.error("phys_addr_of_page: Unable to determine physical address of page\n")

    phys_offset = (page - mem_map_ptr) / self.profile.get_obj_size("page")

    phys_offset = phys_offset << 12

    return phys_offset

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
        # TODO swapper_space support
        #print "no page"

    return page

def get_page_contents(self, inode, idx):

    page = find_get_page(self, inode, idx)

    if page:
        #print "inode: %lx | %lx page: %lx" % (inode, inode.v(), page)

        phys_offset = phys_addr_of_page(self, page)

        phys_as = utils.load_as(self._config, astype = 'physical')

        data = phys_as.read(phys_offset, 4096)
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




