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

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod  as linux_lsmod
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address


### TODO: merge with check_fops
import volatility.plugins.linux.pslist as linux_pslist
from volatility.plugins.linux.slab_info import linux_slabinfo
import volatility.plugins.linux.find_file as find_file

try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False

class linux_check_inline_kernel(linux_common.AbstractLinuxCommand):
    """Check for inline kernel hooks"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

    def _is_hooked(self, sym_addr, modules):
        hook_type = None 
        addr = None    
        counter   = 1 
        prev_op = None

        '''
        if sym_addr != 0xffffffff8114001d:
            return None
        '''

        if self.profile.metadata.get('memory_model', '32bit') == '32bit':
            mode = distorm3.Decode32Bits
        else:
            mode = distorm3.Decode64Bits

        data = self.addr_space.read(sym_addr, 16)
    
        for op in distorm3.Decompose(sym_addr, data, mode):
            if not op.valid:
                continue

            if op.mnemonic == "JMP" and not self.is_known_address(op.operands[0].value, modules):
                hook_type = "JMP"
                addr = 0 # default in case we cannot extract               

                # check for a mov reg, addr; jmp reg;
                if prev_op.mnemonic == "MOV" and prev_op.operands[0].type == 'Register' and op.operands[0].type == 'Register':
                    prev_name = prev_op.operands[0].name
                    
                    # same register
                    if prev_name == op.operands[0].name:
                        addr = prev_op.operands[1].value                        

            elif op.mnemonic == "CALL" and not self.is_known_address(op.operands[0].value, modules):
                hook_type = "CALL"
                addr = op.operands[0].value

            # push xxxx; ret;
            elif counter == 2 and op.mnemonic == "RET":
                if prev_op.mnemonic == "MOV" and prev_op.operands[0].type == 'Register' and  prev_op.operands[0].name in ["RAX", "EAX"]:
                    break

                elif prev_op.mnemonic == "XOR" and prev_op.operands[0].type == 'Register' and prev_op.operands[1].type == 'Register':
                    break

                elif prev_op.mnemonic == "MOV" and prev_op.operands[0].type == 'Register' and  prev_op.operands[1].type == 'Register':
                    break
                
                hook_type = "RET"
                addr = sym_addr

            if hook_type:
                break

            counter = counter + 1
            if counter == 4:
                break

            prev_op = op

        if hook_type:
            ret = hook_type, addr
        else:
            ret = None

        return ret

    #### make api with check_fops
    def _is_inline_hooked(self, ops, op_members, modules):

        for check in op_members:
            addr = ops.m(check)

            if addr and addr != 0:
                hook_info = self._is_hooked(addr, modules)                
                if hook_info:
                    (hook_type, addr) = hook_info
                    yield check, hook_type, addr

    def check_file_cache(self, f_op_members, modules):
        for (_, _, file_path, file_dentry) in find_file.linux_find_file(self._config).walk_sbs():
            for (hooked_member, hook_type, hook_address) in self._is_inline_hooked(file_dentry.d_inode.i_fop, f_op_members, modules):
                yield (file_path, hooked_member, hook_type, hook_address)

    def check_open_files_fop(self, f_op_members, modules):
        # get all the members in file_operations, they are all function pointers
        tasks = linux_pslist.linux_pslist(self._config).calculate()

        for task in tasks: 
            for filp, i in task.lsof():
                for (hooked_member, hook_type, hook_address) in self._is_inline_hooked(filp.f_op, f_op_members, modules):
                    name = "{0:s} {1:d} {2:s}".format(task.comm, i, linux_common.get_path(task, filp))
                    yield (name, hooked_member, hook_type, hook_address)

    def check_proc_fop(self, f_op_members, modules):

        proc_mnt_addr = self.addr_space.profile.get_symbol("proc_mnt")
        if not proc_mnt_addr:
            return

        proc_mnt_ptr = obj.Object("Pointer", offset = proc_mnt_addr, vm = self.addr_space)
        proc_mnt = proc_mnt_ptr.dereference_as("vfsmount")

        root = proc_mnt.mnt_root

        for (hooked_member, hook_type, hook_address) in self._is_inline_hooked(root.d_inode.i_fop, f_op_members, modules):
            yield ("proc_mnt: root", hooked_member, hook_type, hook_address)

        # only check the root directory
        for dentry in root.d_subdirs.list_of_type("dentry", "d_u"):

            name = dentry.d_name.name.dereference_as("String", length = 255)
            
            for (hooked_member, hook_type, hook_address) in self._is_inline_hooked(dentry.d_inode.i_fop, f_op_members, modules): 
                yield("proc_mnt: {0}".format(name), hooked_member, hook_type, hook_address)
    
    def walk_proc(self, cur, f_op_members, modules, parent = ""):
        while cur:
            if cur.obj_offset in self.seen_proc:
                cur = cur.next
                continue

            self.seen_proc[cur.obj_offset] = 1

            name = parent + "/" +  self.addr_space.read(cur.name.obj_offset, cur.namelen + 1)
            idx = name.find("\x00")
            if idx != -1:
                name = name[:idx]
           
            fops = cur.proc_fops

            for (hooked_member, hook_type, hook_address) in self._is_inline_hooked(fops, f_op_members, modules):
                yield (name, hooked_member, hook_type, hook_address)

            subdir = cur.subdir

            while subdir:
                for (sub_name, hooked_member, hook_type, hook_address) in self.walk_proc(subdir, f_op_members, modules, name):
                    yield (sub_name, hooked_member, hook_type, hook_address)
                subdir = subdir.next

            cur = cur.next

    def check_proc_root_fops(self, f_op_members, modules):   
        self.seen_proc = {}
 
        proc_root_addr = self.addr_space.profile.get_symbol("proc_root") 
        proc_root = obj.Object("proc_dir_entry", offset = proc_root_addr, vm = self.addr_space)

        for (hooked_member, hook_type, hook_address) in self._is_inline_hooked(proc_root.proc_fops, f_op_members, modules):
            yield("proc_root", hooked_member, hook_type, hook_address)

        for (name, hooked_member, hook_type, hook_address) in self.walk_proc(proc_root, f_op_members, modules):
            yield (name, hooked_member, hook_type, hook_address) 

    #### end make api with check_fops

    def _check_file_op_pointers(self, modules):
        funcs = [self.check_open_files_fop, self.check_proc_fop, self.check_proc_root_fops, self.check_file_cache]

        f_op_members = self.profile.types['file_operations'].keywords["members"].keys()
        f_op_members.remove('owner')

        for func in funcs:
            for (name, member, hook_type, address) in func(f_op_members, modules):
                yield (name, member, hook_type, address)

    def check_afinfo(self, var_name, var, op_members, seq_members, modules):
        for (hooked_member, hook_type, hook_address) in self._is_inline_hooked(var.seq_fops, op_members,  modules):
            yield (var_name, hooked_member, hook_type, hook_address)

        # newer kernels
        if hasattr(var, "seq_ops"):
            for (hooked_member, hook_type, hook_address) in self._is_inline_hooked(var.seq_ops, seq_members, modules):
                yield (var_name, hooked_member, hook_type, hook_address) 
 
    def _check_afinfo(self, modules):
        op_members  = self.profile.types['file_operations'].keywords["members"].keys()
        seq_members = self.profile.types['seq_operations'].keywords["members"].keys()       

        tcp = ("tcp_seq_afinfo", ["tcp6_seq_afinfo", "tcp4_seq_afinfo"])
        udp = ("udp_seq_afinfo", ["udplite6_seq_afinfo", "udp6_seq_afinfo", "udplite4_seq_afinfo", "udp4_seq_afinfo"])
        protocols = [tcp, udp]

        for proto in protocols:
            struct_type = proto[0]

            for global_var_name in proto[1]:
                global_var_addr = self.addr_space.profile.get_symbol(global_var_name)

                if not global_var_addr:
                    continue

                global_var = obj.Object(struct_type, offset = global_var_addr, vm = self.addr_space)

                for (name, member, hook_type, address) in self.check_afinfo(global_var_name, global_var, op_members, seq_members, modules):
                    yield (name, member, hook_type, address)
         
    def _check_inetsw(self, modules):
        try:
            self.addr_space.profile.get_obj_offset("inet_protosw", "list")
        except KeyError:
            debug.warning("You are using an old Linux profile. Please recreate the profile using the latest Volatility version.")
            return

        proto_members = self.profile.types['proto_ops'].keywords["members"].keys()       
        proto_members.remove('owner')
        proto_members.remove('family')
        
        inetsw_addr = self.addr_space.profile.get_symbol("inetsw")
        inetsw = obj.Object(theType = "Array", targetType = "list_head", offset = inetsw_addr, vm = self.addr_space, count = 11)
 
        for inet_list in inetsw:
            for inet in inet_list.list_of_type("inet_protosw", "list"):
                name = self.addr_space.read(inet.prot.name.obj_offset, 32)
                idx = name.index("\x00")
                if idx != -1:   
                    name = name[:idx]

                for (hooked_member, hook_type, hook_address) in self._is_inline_hooked(inet.ops, proto_members,  modules):
                    yield (name, hooked_member, hook_type, hook_address)

    def _check_known_functions(self, modules):
        known_funcs = ["dev_get_flags", "vfs_readdir", "tcp_sendmsg"]

        for func_name in known_funcs:
            func_addr = self.profile.get_symbol(func_name)

            if func_addr:
                hook_info = self._is_hooked(func_addr,  modules)
                if hook_info:
                    (hook_type, hook_address) = hook_info
                    yield (func_name, "", hook_type, hook_address)        

    def calculate(self):
        linux_common.set_plugin_members(self)
       
        if not has_distorm3:
            debug.error("This plugin cannot operate without distrom installed.")

        modules  = linux_lsmod.linux_lsmod(self._config).get_modules()       
 
        funcs = [self._check_known_functions, self._check_file_op_pointers, self._check_afinfo, self._check_inetsw]
        
        for func in funcs:
            for (sym_name, member, hook_type, sym_addr) in func(modules):
                yield (sym_name, member, hook_type, sym_addr)

    def unified_output(self, data):
        return TreeGrid([("Name", str),
                       ("Member", int),
                       ("HookType", str),
                       ("HookAddress", Address)],
                        self.generator(data))

    def generator(self, data):
        for (sym_name, member, hook_type, sym_addr) in data:
            yield (0, [str(sym_name), str(member), str(hook_type), Address(sym_addr)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "48"),
                                  ("Member", "16"),
                                  ("Hook Type", "8"),
                                  ("Hook Address", "[addrpad]")])

        for (sym_name, member, hook_type, sym_addr) in data:
            self.table_row(outfd, sym_name, member, hook_type, sym_addr)

