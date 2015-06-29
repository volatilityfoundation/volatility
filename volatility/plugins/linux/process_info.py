#
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

"""
@author:       Edwin Smulders
@license:      GNU General Public License 2.0 or later
@contact:      mail@edwinsmulders.eu
"""

import struct
import collections
import itertools

import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.proc_maps as linux_proc_maps
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.threads as linux_threads


# Because we want to address registers like "registers.eip"
# TODO: replace with linux_info_regs
registers = collections.namedtuple('registers',
                                   [
                                       'r15', 'r14', 'r13', 'r12',
                                       'rbp', 'rbx',
                                       'r11', 'r10', 'r9', 'r8',
                                       'rax', 'rcx', 'rdx',
                                       'rsi', 'rdi',
                                       'unknown',
                                       'rip',
                                       'cs', 'eflags', 'rsp', 'ss'
                                       ])

# TODO: these were the initial registers, they might be valid for x86
# To investigate: view kernel stack using this module
# compare using "info r" in gdb.
# registers = collections.namedtuple('registers',
#                                    ['bla1', 'bla2','bla3','bla4', 'ebx', 'ecx', 'edx',
#                                     'esi', 'edi', 'ebp',
#                                     'eax', 'eds', 'ees',
#                                     'efs', 'egs', 'orig_eax',
#                                     'eip', 'ecs', 'flags',
#                                     'esp', 'ess',
#                                    ]) #test


#registers = collections.namedtuple('registers', ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'eds', 'ees', 'efs', 'egs', 'orig_eax', 'eip', 'ecs', 'flags', 'esp', 'ess'])

address_size = 8

# Helper functions
def null_list(pages, size):
    """
    Split a section (divided by pages) on 0-bytes.

    @param pages: a list of pages
    @param size: total size of the section
    @return: a list of strings
    """
    res = []
    for page in pages:
        if size > 4096:
            size -= 4096
        else:
            page = page[:size]
            for s in page.split('\0'):
                if s != "":
                    res.append(s)
    return res


def int_list(pages, size):
    """
    Split a range into integers. Will split into words (e.g. 4 or 8 bytes).

    @param pages: a list of pages
    @param size: total size of the section
    @return: a list of word-sized integers
    """
    if address_size == 4:
        fmt = "<L"
    else:
        fmt = "<Q"
    for page in pages:
        curr = 0
        while curr < 4096 and curr < size:
            yield struct.unpack(fmt, page[curr:curr + address_size])[0]
            curr += address_size


# workaround for a bug, it is fixed by now
def _neg_fix(addr):
    return addr
    #return 0xffffffff + addr if addr < 0 else addr


# print as hex (0x12345678)
def print_hex(value):
    """Print a value as in 4 byte hexadecimal."""
    print("0x{:08x}".format(value))


def read_addr_range(start, end, addr_space):
    """
    Read a number of pages.

    @param start: Start address
    @param end: End address
    @param addr_space: The virtual address space
    @return: a list of pages
    """
    pagesize = 4096
    # xrange doesn't support longs :(
    while start < end:
        page = addr_space.zread(start, pagesize)
        yield page
        start += pagesize


def read_null_list( start, end, addr_space):
    """
    Read a number of pages and split it on 0-bytes.

    @param start: Start address
    @param end: End address
    @param addr_space: The virtual address space
    @return: a list of strings
    """
    return null_list(read_addr_range(start, end, addr_space), end - start)

def read_int_list( start, end, addr_space):
    """
    Read a number of pages and split it into integers.

    @param start: Start address
    @param end: End address
    @param addr_space: The virtual address space
    @return: a list of integers.
    """
    return int_list(read_addr_range(start, end, addr_space), end - start)

def read_registers(task, addr_space):
    """
    Read registers from kernel space. Needs to be replaced by the linux_info_regs plugin.

    @param task: The relevant task_struct
    @param addr_space: The kernel address space
    @return: A list of registers (integers)
    """
    return list(
        read_int_list(
            task.thread.sp0 - (21 * address_size),
            task.thread.sp0,
            addr_space
        )
    )

# Main command class
class linux_process_info:
    """ Plugin to gather info for a task/process. Extends pslist. """

    def __init__(self, config, *args, **kwargs):
        linux_common.set_plugin_members(self)
        global address_size
        if self.profile.metadata.get('memory_model', '32bit') == '32bit':
            address_size = 4
        else:
            address_size = 8
        self.get_threads = linux_threads.linux_threads(config).get_threads

    def read_addr_range(self, start, end, addr_space=None):
        """ Read an address range with the task address space as default.

        @param start: Start address
        @param end: End address
        @param addr_space: The address space to read.
        @return: a list of pages
        """
        if addr_space == None:
            addr_space = self.proc_as
        return read_addr_range(start, end, addr_space)

    def calculate(self):

        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            self.task = task

            # Yield a process object
            yield self.analyze(task)

    def read_null_list(self, start, end, addr_space=None):
        """
        Read a number of pages and split it on 0-bytes, with the task address space as default.

        @param start: Start address
        @param end: End address
        @param addr_space: The virtual address space
        @return: a list of strings
        """
        return null_list(self.read_addr_range(start, end, addr_space), end - start)

    def read_int_list(self, start, end, addr_space=None):
        """
        Read a number of pages and split it into integers, with the task addres space as default.

        @param start: Start address
        @param end: End address
        @param addr_space: The virtual address space
        @return: a list of integers.
        """
        return int_list(self.read_addr_range(start, end, addr_space), end - start)

    def analyze(self, task):
        """
        Analyze a task_struct.

        @param task: the task_struct
        @return: a process_info object
        """
        self.proc_as = task.get_process_address_space()
        p = process_info(task)
        p.kernel_as = self.addr_space
        #print(p.stack)
        #linux_volshell.linux_volshell(self._config).render_text.dt('mm_struct')
        #linux_volshell.linux_volshell(self._config).render_text.dt('mm_struct', task.mm)

        # kernel thread?
        p.maps = list(task.get_proc_maps())
        if len(p.maps) == 0:
            return None
        for m in p.maps:
            if m.vm_start <= task.mm.start_stack <= m.vm_end:
                p.vm_stack_low = m.vm_start
                p.vm_stack_high = m.vm_end

        if not p.vm_stack_low:
            last = p.maps[-1]
            p.vm_stack_high = last.vm_end
            p.vm_stack_low = last.vm_start


        p.env = self.read_null_list(_neg_fix(task.mm.env_start), _neg_fix(task.mm.env_end))
        # We care only about the actual stack, not arguments and such
        p.stack = self.read_int_list(_neg_fix(p.vm_stack_low), _neg_fix(task.mm.start_stack))
        p.rest_stack = self.read_int_list(_neg_fix(task.mm.start_stack), _neg_fix(task.mm.env_start))
        p.args = self.read_null_list(_neg_fix(task.mm.arg_start), _neg_fix(task.mm.arg_end))

        reglist = read_registers(task, self.addr_space)
        p.reg = registers(*reglist)
        p.threads = self.get_threads(task)[1]

        return p

    def get_map(self, task, address):
        """
        Get the vm_area to which an address points.

        @param task: the task_struct
        @param address: an address
        @return: a vm_area_struct corresponding to the address
        """
        for m in task.get_proc_maps():
            if m.vm_start <= address <= m.vm_end:
                return m

    def render_text(self, outfd, data):
        self.outfd = outfd
        #pm = linux_proc_maps.linux_proc_maps(self._config)
        #pm.render_text(outfd, pm.calculate())
        #for process in data:
            #mm = process.task.mm
            #print("Heap  Start: {0} End: {1}".format(hex(mm.start_brk), hex(mm.brk)))
            #print("Stack Start: {0} End: {1}".format(hex(mm.start_stack), hex(mm.arg_start)))
            #print("Args  Start: {0} End: {1}".format(hex(mm.arg_start), hex(mm.arg_end)))
            #print("Env   Start: {0} End: {1}".format(hex(mm.env_start), hex(mm.env_end)))
            #self.render_registers(process.reg)
            #main_addrspace = process.task.get_process_address_space()
            #print(main_addrspace, self.addr_space)
            #print(process.task.mm.mm_users.d())
            # outfd.write("{:16s} {:6s} {:18s} {:18s} {:18s}\n".format(
            #     "Thread Name",
            #     "PID",
            #     "task.thread.usersp",
            #     "task.thread.sp0",
            #     "Register esp"
            # ))
    #         for task in process.threads:
    #             #print(task.thread.d())
    #             #thread_p = self.analyze(task)
    #             #proc_as = task.get_process_address_space()
    #             map = self.get_map(task, task.thread.usersp)
    #             map_flags = map.vm_flags
    #             if not map_flags.is_readable() or not map_flags.is_writable() or map.vm_file != 0:
    #                 outfd.write("File {}\n".format(map.vm_file))
    #                 outfd.write("{:16s} {:6s} 0x{:016x} 0x{:016x} 0x{:016x} 0x{:016x} 0x{:016x}\n".format(
    #                     task.comm,
    #                     str(task.pid),
    #                     task.thread.usersp,
    #                     task.thread.sp0,
    #                     #thread_p.reg.esp,
    #                     0,
    #                     map.vm_start,
    #                     map.vm_end
    # #                    task.get_process_address_space().vtop(reg.esp),
    # #                    main_addrspace.vtop(reg.esp)
    #
    #                 ))
    #             else:
    #                 outfd.write("Map looked like stack\n")
            #cProfile.run("self.render_list(process.get_pointers())")
            #self.render_list(process.get_unique_data_pointers())
            #self.render_list(process.get_data_pointers_from_heap())
            #self.render_annotated_list(process.annotated_stack())
            # still broken
            #self.render_stack_frames(process.stack_frames)
            #exit(0)
            #self.render_annotated_list(stack)kleutvieul

    def render_stack_frames(self, stack_frames):
        """
        Render stackframes (old code)
        @param stack_frames: a list of stackframes
        @return: None
        """
        for stack_frame in stack_frames:
            self.table_header(self.outfd, [('Stack Frame', '16'), ('Value', '[addrpad]')])
            self.table_row(self.outfd, "Frame Number", stack_frame.frame_number)
            self.table_row(self.outfd, "Offset", stack_frame.offset)
            self.table_row(self.outfd, "Return Address", stack_frame.ret)

    def render_registers(self, reg):
        """
        Render a registers named tuple.
        @param reg: registers named tuple
        @return: None
        """
        self.table_header(self.outfd, [('Register', '8'), ('Value', '[addrpad]')])
        for k in reg._fields:
            self.table_row(self.outfd, k, getattr(reg, k))

    def render_list(self, l):
        """
        Render an address list
        @param l: address list
        @return: None
        """
        self.table_header(self.outfd, [('Address', '[addrpad]'), ('Value', '[addrpad]')])
        for address, value in l:
            self.table_row(self.outfd, address, value)

    def render_annotated_list(self, ann_list):
        """
        Render a list including annotations.
        @param ann_list: a 3-tuple list
        @return: None
        """
        self.table_header(self.outfd, [('Address', '[addrpad]'), ('Value', '[addrpad]'), ('Annotation', '50')])
        for (address, value, annotation) in ann_list:
            self.table_row(self.outfd, address, value, annotation)


class process_info(object):
    """
    A class to collect various information about a process/task. Includes helper functions to detect pointers.
    """

    def __init__(self, task):
        self.task = task
        self.mm = task.mm


        ####
        # obj.CType is really slow (__getattr__), so we do this
        self.mm_brk = _neg_fix(self.mm.brk)
        self.mm_end_code = _neg_fix(self.mm.end_code)
        self.mm_end_data = _neg_fix(self.mm.end_data)
        self.mm_env_end = _neg_fix(self.mm.env_end)
        self.mm_start_brk = _neg_fix(self.mm.start_brk)
        self.mm_start_code = _neg_fix(self.mm.start_code)
        self.mm_start_data = _neg_fix(self.mm.start_data)
        ####

        self.proc_as = task.get_process_address_space()
        self.kernel_as = None
        self.env = None
        self.rest_stack = None
        self.args = None
        self.vm_stack_low = None
        self.vm_stack_high = None
        self.stack_frames = None
        #self.threads = None
        self.thread_stacks = None
        self.thread_stack_ranges = None

        # properties
        self._stack = None
        self._threads = None
        self._reg = None
        self._real_stack_low = None
        self._maps = None
        self._exec_maps = None
        self._exec_maps_ranges = None

        self.is_pointer_dict = dict(stack=self.is_stack_pointer, heap=self.is_heap_pointer,
                                    constant=self.is_constant_pointer, code=self.is_code_pointer)

    @property
    def maps(self):
        """
        @return: the vm_area maps list.
        """
        return self._maps

    @maps.setter
    def maps(self, value):
        """
        Setter for maps. Also initializes some other values.
        @param value: The list of vm_area maps
        @return: None
        """
        self._maps = value
        self._exec_maps = []
        self._exec_maps_ranges = []
        for m in self._maps:
            if m.vm_flags.is_executable():
                self._exec_maps.append(m)
                self._exec_maps_ranges.append((m.vm_start, m.vm_end))

    @property
    def reg(self):
        """
        @return: the registers named tuple for this process
        """
        return self._reg

    @reg.setter
    def reg(self, value):
        """
        Setter for reg.
        @param value: The named tuple for registers.
        @return: None
        """
        self._reg = value
        #self._generate_stack_frames()

    @property
    def stack(self):
        """
        Get the _list_ of stack values (old code).
        @return: stack integer list.
        """
        return self._stack

    @stack.setter
    def stack(self, value):
        """
        Set the stack list (old code).
        @param value: a list of integers.
        @return: None
        """
        self._stack = list(value)
        self._calculate_stack_offset()
        #self._generate_thread_stack_list()
        #self._generate_stack_frames()

    @property
    def threads(self):
        """
        Get the list of threads for this process.
        @return: a list of task_structs (threads).
        """
        return self._threads

    @threads.setter
    def threads(self, value):
        """
        Set the list of threads. Initializes the list of register tuples for these threads.
        @param value: The list of task_structs.
        @return: None
        """
        self._threads = value
        self.thread_registers = self._find_thread_registers()
        self._generate_thread_stack_list()

    def _find_thread_registers(self):
        """
        Reads the registers from the kernel stack for all threads.
        @return: list of tuple of registers.
        """
        reglist = []
        for task in self.threads:
            reglist.append(registers(*read_registers(task, self.kernel_as)))
        return reglist


    def get_stack_value(self, address):
        """
        Read a value from the stack, by using the stack list (old code).
        @param address: The address to read.
        @return: The word at this address.
        """
        return self.stack[self.get_stack_index(address)]

    def get_stack_index(self, address):
        """
        Calculates the index on the stack list given an address.
        @param address: The address to find
        @return: an index into process_info.stack
        """
        return (address - self.vm_stack_low) / address_size

    def _generate_thread_stack_list(self):
        """
        Makes a list of the stack vm areas for all threads. Uses the register contents.
        @return: None
        """
        if not self.threads or not self.maps:
            self.thread_stacks = None
        else:
            thread_sps = [self.thread_registers[i].rsp for i, task in enumerate(self.threads)]
            thread_sps.sort()
            self.thread_stacks = []
            self.thread_stack_ranges = []
            #for i in range(len(thread_sps)):
            i = 0
            for m in self.maps:
                if i < len(thread_sps) and m.vm_start <= thread_sps[i] <= m.vm_end:
                    self.thread_stacks.append(m)
                    self.thread_stack_ranges.append((m.vm_start, m.vm_end))
                    i+=1

    def _calculate_stack_offset(self):
        """
        Calculates the absolute bottom of the stack (everything below is 0). (old code)
        @return: The lowest stack address.
        """
        offset = self.vm_stack_low
        for i in self._stack:
            if i != 0:
                self._real_stack_low = offset
                break
            offset += 4
        return self._real_stack_low

    def annotate_addr_list(self, l, offset=None, skip_zero=True):
        """
        Annotates a list of addresses with some basic pointer and register information (old code).
        @param l: list of addresses.
        @param offset: Offset of the list
        @param skip_zero:
        @return: An annotated list
        """
        if offset == None:
            offset = self.vm_stack_low
        for value in l:
            if value != 0:
                skip_zero = False
            pointer_type = self.get_pointer_type(value)
            annotation = ""
            if pointer_type != None:
                annotation = pointer_type + " pointer"
            if offset == self.reg.esp:
                annotation += " && register esp"
            elif offset == self.reg.ebp:
                annotation += " && register ebp"
            if not skip_zero:
                yield (offset, value, annotation)
            offset += 4

    def is_stack_pointer(self, addr):
        """
        Check if addr is a pointer to the (main) stack.
        @param addr: An address
        @return: True or False
        """
        return self.vm_stack_low <= addr <= self.mm_env_end

    def is_thread_stack_pointer(self, addr):
        """
        Check if addr is a pointer to a thread stack.
        FIXME: enable checking a specific stack.
        @param addr: An address
        @return: True or False
        """
        for m_start, m_end in self.thread_stack_ranges:
            if m_start <= addr <= m_end:
                return True
        return False

    def is_heap_pointer(self, addr):
        """
        Check if addr is a pointer to the heap.
        @param addr: An address
        @return: True or False
        """
        return self.mm_start_brk <= addr <= self.mm_brk

    def is_constant_pointer(self, addr):
        """
        Check if addr is a pointer to a program constant
        @param addr: An address
        @return: True of False
        """
        return self.mm_start_data <= addr <= self.mm_end_data

    def is_program_code_pointer(self, addr):
        """
        Check if addr is a pointer to the program code
        @param addr: An address
        @return: True of False
        """
        return self.mm_start_code <= addr <= self.mm_end_code

    def is_library_code_pointer(self, addr):
        """
        Check if addr is a pointer to library code
        @param addr: An address
        @return: True or False
        """
        return self.is_code_pointer(addr) and not self.is_program_code_pointer(addr)

    def is_code_pointer(self, addr):
        """
        Check if addr is a pointer to an executable section of memory
        @param addr: An address
        @return: True or False
        """
        for m_start, m_end in self._exec_maps_ranges:
            if m_start <= addr <= m_end:
                return True
        return False

    def is_data_pointer(self, addr):
        """
        Check if addr points to data (not code)
        @param addr: An address
        @return: True or False
        """
        return self.is_heap_pointer(addr) or self.is_stack_pointer(addr) or self.is_constant_pointer(addr) or self.is_thread_stack_pointer(addr)

    def is_pointer(self, addr, space=None):
        """
        Check if addr is any sort of pointer
        @param addr: An address
        @param space: A choice of stack, heap, etc
        @return: True or False
        """
        if not space:
            for func in self.is_pointer_dict.itervalues():
                if func(addr):
                    return True
            return False
        else:
            return self.is_pointer_dict[space]

    def get_map_by_name(self, name, permissions='r-x'):
        """
        Find a memory mapping (vm_area) by its name (not exact match). Optionally, check permissions.
        @param name: The mapped name to find.
        @param permissions: Permissions in 'rwx' format
        @return: A (vm_start, vm_end, libname) tuple or None
        """
        # We use this to find libc
        for vma in self.task.get_proc_maps():
            libname = linux_common.get_path(self.task, vma.vm_file)
            # just look for partial name
            if str(vma.vm_flags) == permissions and name in libname:
                return vma.vm_start, vma.vm_end, libname
        return None

    def get_unique_data_pointers(self):
        """
        A filter over get_data_pointers() to get only unique values.
        @return: A iterator of pointers.
        """
        return self.get_unique_pointers(self.get_data_pointers())

    def get_unique_pointers(self, pointer_iter=None):
        """
        Filter an iterator to only return unique values.
        @param pointer_iter: The pointer iterator to use. If None, use get_pointers().
        @return: An iterator of unique pointers
        """
        if pointer_iter == None:
            pointer_iter = self.get_pointers()

        store = []
        
        for address, value in pointer_iter:
            if value not in store:
                yield address, value
                store.append(value)

    def get_data_pointers(self):
        """
        Calls get_pointers with self.is_data_pointer as a filter.
        @return: An iterator of pointers
        """
        return self.get_pointers(self.is_data_pointer)

    def get_pointers(self, cond=None, space=None):
        """
        Finds pointers given a condition and a space. (old code)
        @param cond: The type of pointer to filter, defaults to self.is_pointer
        @param space: The list of values to use, defaults to self.stack
        @return: An iterator of addresses and their values.
        """
        if cond == None:
            cond = self.is_pointer
        if space == None:
            space = self.stack
        address = self.vm_stack_low
        for value in space:
            if value != 0 and cond(value):
                yield address, value
            address += address_size

    def get_data_pointers_from_heap(self):
        """
        Find data pointers on the heap, very slow.
        @return: An iterator of pointers
        """
        return self.get_pointers(
            cond = self.is_data_pointer,
            space = read_int_list(self.mm_start_brk, self.mm_brk, self.proc_as)
        )

    def get_data_pointers_from_map(self, m):
        """
        Find data pointers from a specific mapping, very slow.
        @param m: The vm_area map
        @return: An iterator of pointers
        """
        return self.get_pointers(
            cond = self.is_data_pointer,

            space = read_int_list(m.vm_start, m.vm_end, self.proc_as)
        )

    def get_data_pointers_from_threads(self):
        """
        Find data pointers from all threads
        @return: An iterator of all pointers on thread stacks
        """
        iterators = [self.get_data_pointers_from_map(m) for m in self.thread_stacks]
        return self.get_unique_pointers(itertools.chain(*iterators))

    def get_pointers_from_stack(self):
        """
        Find pointers on the main stack
        @return: An iterator of pointers
        """
        return self.get_pointers(space=self.stack)

    def get_pointer_type(self, addr):
        """
        Determine the pointer type for a specific address.
        @param addr: An address.
        @return: String pointer type
        """
        for k, v in self.is_pointer_dict.iteritems():
            if v(addr):
                return k
        return None

    def annotated_stack(self):
        """
        Uses annotate_addr_list() to annotate the stack.
        @return: An annotated address list of the stack
        """
        return self.annotate_addr_list(self._stack)



