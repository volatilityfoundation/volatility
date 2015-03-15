# Volatility
# Copyright (C) 2010 Brendan Dolan-Gavitt
# Copyright (c) 2011 Michael Cohen <scudette@gmail.com>
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

import re,copy
import sys, os
import zipfile
import struct
import time
from operator import attrgetter
import volatility.plugins as plugins
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.overlays.basic as basic
import volatility.addrspace as addrspace
import volatility.scan as scan
import volatility.plugins.addrspaces.amd64 as amd64
import volatility.plugins.addrspaces.intel as intel
import volatility.plugins.overlays.native_types as native_types
import volatility.utils as utils
import volatility.plugins.mac.common as common

x64_native_types = copy.deepcopy(native_types.x64_native_types)

x64_native_types['long'] = [8, '<q']
x64_native_types['unsigned long'] = [8, '<Q']

dyld_vtypes = {
    'dyld32_image_info' : [12, {
         'imageLoadAddress' : [0, ['pointer', ['unsigned int']]],
         'imageFilePath'    : [4, ['pointer', ['char']]],
         'imageFileModDate' : [8, ['pointer', ['unsigned int']]],  
         }],
    
    'dyld32_all_image_infos' : [20 , {
        'version'           : [0, ['unsigned int']],
        'infoArrayCount'    : [4, ['unsigned int']],
        'infoArray'         : [8, ['pointer', ['dyld32_image_info']]],
        'notification'      : [12, ['pointer', ['void']]],
        'processDetachedFromSharedRegion': [16, ['unsigned int']],
    }],

    'dyld64_image_info' : [24, {
         'imageLoadAddress' : [0, ['pointer', ['unsigned int']]],
         'imageFilePath'    : [8, ['pointer', ['char']]],
         'imageFileModDate' : [16, ['pointer', ['unsigned int']]],  
         }],
    
    'dyld64_all_image_infos' : [28 , {
        'version'           : [0,  ['unsigned int']],
        'infoArrayCount'    : [4,  ['unsigned int']],
        'infoArray'         : [8,  ['pointer', ['dyld64_image_info']]],
        'notification'      : [16, ['pointer', ['void']]],
        'processDetachedFromSharedRegion': [24, ['unsigned int']],
    }],
}

class DyldTypes(obj.ProfileModification):
    conditions = {"os" : lambda x : x in ["mac"]}

    def modification(self, profile):
        profile.vtypes.update(dyld_vtypes)

mig_vtypes_32 = {
    'mig_hash_entry' : [16, {
         'num'       : [0, ['int']],
         'routine'   : [4, ['pointer', ['void']]],
         'size'      : [8, ['int']],  
         'callcount' : [12, ['unsigned int']],  
         }],
}

mig_vtypes_64 = {
    'mig_hash_entry' : [24, {
         'num'       : [0, ['long long']],
         'routine'   : [8, ['pointer', ['void']]],
         'size'      : [16, ['int']],  
         'callcount' : [20, ['unsigned int']],  
         }],
}

class MigTypes(obj.ProfileModification):
    conditions = {"os" : lambda x : x in ["mac"]}

    def modification(self, profile):
        if profile.metadata.get('memory_model', '32bit') == "32bit":
            profile.vtypes.update(mig_vtypes_32)
        else:
            profile.vtypes.update(mig_vtypes_64)


class catfishScan(scan.BaseScanner):
    """ Scanner for Catfish string for Mountain Lion """
    checks = []

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles}) ]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def _get_dtb_pre_m_lion(self):
        profile = self.obj_vm.profile

        if self.obj_vm.profile.metadata.get('memory_model', '32bit') == "32bit":
            ret = profile.get_symbol("_IdlePDPT")
            # on 10.5.x the PDTD symbol is a pointer instead of an array like 10.6 and 10.7
            if ret % 0x1000:
                ret = self.obj_vm.read(ret, 4)
                ret = struct.unpack("<I", ret)[0]
        else:
            ret = profile.get_symbol("_IdlePML4")
            # so it seems some kernels don't define this as the physical address, but actually the virtual
            # while others define it as the physical, easy enough to figure out on the fly
            if ret > 0xffffff8000000000:
                ret = ret - 0xffffff8000000000

        return ret

    ## Based off volafox's method for finding vm_kernel_shift through loGlo & hardcoded Catfish
    def _get_dtb_m_lion(self):
        tbl = self.obj_vm.profile.sys_map["kernel"]
        config = self.obj_vm.get_config()

        if config.SHIFT:
            shift_address = config.SHIFT
        else:
            scanner = catfishScan(needles = ["Catfish \x00\x00"])
            for catfish_offset in scanner.scan(self.obj_vm):
                shift_address = catfish_offset - (tbl["_lowGlo"][0][0] % 0xFFFFFF80)
                break

        self.obj_vm.profile.shift_address = shift_address

        bootpml4 = (tbl["_BootPML4"][0][0] % 0xFFFFFF80) + shift_address
        boot_pml4_dtb = amd64.AMD64PagedMemory(self.obj_vm, config, dtb = bootpml4)
      
        idlepml4_addr = (tbl['_IdlePML4'][0][0]) + shift_address
        idlepml4_ptr = obj.Object("unsigned int", offset = idlepml4_addr, vm = boot_pml4_dtb)

        return idlepml4_ptr.v()

    def generate_suggestions(self):
        profile = self.obj_vm.profile
        bootpml = profile.get_symbol("_BootPML4")
        
        if bootpml:        
            ret = self._get_dtb_m_lion()
        else:
            ret = self._get_dtb_pre_m_lion()                  
        
        yield ret

class VolatilityMacIntelValidAS(obj.VolatilityMagic):
    """An object to check that an address space is a valid Mac Intel Paged space"""

    def _set_profile_metadata(self, version):

        start = version[len("Darwin Kernel Version "):]
        idx = start.find(":")
        (major, minor, _) = [int(x) for x in start[:idx].split(".")]

        setattr(self.obj_vm.profile, '_md_major', major)
        setattr(self.obj_vm.profile, '_md_minor', minor)

    def generate_suggestions(self):
        version_addr = self.obj_vm.profile.get_symbol("_version")

        string = self.obj_vm.read(version_addr, 60)

        if string and string.startswith("Darwin"):
            self._set_profile_metadata(string)
            yield True
        else:
            yield False

class ifnet(obj.CType):
    def sockaddr_dl(self):
        if hasattr(self, "if_lladdr"):
            ret = obj.Object("sockaddr_dl", offset = self.if_lladdr.ifa_addr.v(), vm = self.obj_vm)
        else:
            ret = obj.Object("sockaddr_dl", offset = self.if_addrhead.tqh_first.ifa_addr.v(), vm = self.obj_vm)

        return ret

class vnode(obj.CType):
    def is_dir(self):
        return self.v_type == 2

    def is_reg(self):
        return self.v_type == 1

    def _do_calc_path(self, ret, vnodeobj, vname):
        if vnodeobj == None:
            return 

        if vname:
            ret.append(vname)

        if vnodeobj.v_flag.v() & 0x000001 != 0 and vnodeobj.v_mount.v() != 0: 
            if vnodeobj.v_mount.mnt_vnodecovered.v() != 0:
                self._do_calc_path(ret, vnodeobj.v_mount.mnt_vnodecovered, vnodeobj.v_mount.mnt_vnodecovered.v_name)
        else:  
            self._do_calc_path(ret, vnodeobj.v_parent, vnodeobj.v_parent.v_name)
                
    def full_path(self):
        if self.v_flag.v() & 0x000001 != 0 and self.v_mount.v() != 0 and self.v_mount.mnt_flag.v() & 0x00004000 != 0:
            ret = "/"
        else: 
            elements = []
            files = []

            self._do_calc_path(elements, self, self.v_name)
            elements.reverse()

            for e in elements:
                files.append(str(e.dereference()))

            ret = "/".join(files)                
            if ret:
                ret = "/" + ret

        return ret

    def get_contents(self):
        moc  = self.v_un.vu_ubcinfo.ui_control.moc_object
        memq = moc.memq 

        cur = memq.m("next").dereference_as("vm_page")

        file_size = self.v_un.vu_ubcinfo.ui_size
        
        phys_as = utils.load_as(self.obj_vm.get_config(), astype = 'physical')
        
        while cur and cur.is_valid() and cur.offset < file_size:
            buf = phys_as.zread(cur.phys_page * 4096, 4096)              

            yield (cur.offset.v(), buf)
 
            cur = cur.listq.next.dereference_as("vm_page")

class fileglob(obj.CType):
    
    @property
    def fg_type(self):
        ret = self.members.get("fg_type")
        if ret:
            ret = self.m("fg_type")
        else:    
            ret = self.fg_ops.fo_type

        ret = str(ret)
        return ret
     
class kauth_scope(obj.CType):
    @property
    def ks_identifier(self):
        ident_ptr = self.m("ks_identifier")
        ident = self.obj_vm.read(ident_ptr, 256)
        if ident:
            idx = ident.find("\x00")
            if idx != -1:
                ident = ident[:idx]  

        return ident

    def listeners(self):
        ls_array = obj.Object(theType="Array", targetType="kauth_local_listener", offset = self.m("ks_listeners").obj_offset, vm = self.obj_vm, count = 16)    
        for ls in ls_array:
            if ls.is_valid() and ls.kll_callback != 0:
                yield ls 

class thread(obj.CType):   
    def start_time(self):
        baddr = self.obj_vm.profile.get_symbol("_clock_boottime")     

        boot_time = obj.Object("unsigned long long", offset = baddr, vm = self.obj_vm)
        abs_time  = boot_time + self.sched_stamp 

        try:
            data = struct.pack("<I", abs_time)
        except struct.error:
            return ""

        bufferas = addrspace.BufferAddressSpace(self.obj_vm.get_config(), data = data)
        dt = obj.Object("UnixTimeStamp", offset = 0, vm = bufferas, is_utc = True)

        return dt

class proc(obj.CType):   
    def __init__(self, theType, offset, vm, name = None, **kwargs):
        self.pack_fmt  = ""
        self.pack_size = 0
        self.addr_type = ""
 
        obj.CType.__init__(self, theType, offset, vm, name, **kwargs)
        
        bit_string = str(self.task.map.pmap.pm_task_map or '')[9:]        
        if bit_string.find("64BIT") == -1:
            self.pack_fmt = "<I"
            self.pack_size = 4
            self.addr_type = "unsigned int"
        else:
            self.pack_fmt = "<Q"
            self.pack_size = 8
            self.addr_type = "unsigned long long"
      
    def bash_hash_entries(self):
        proc_as = self.get_process_address_space()
        
        # In cases when mm is an invalid pointer 
        if not proc_as:
            return

        bit_string = str(self.task.map.pmap.pm_task_map or '')[9:]
        if bit_string.find("64BIT") == -1:
            addr_type       = "unsigned int"
            bucket_contents_type =  "mac32_bucket_contents"
            htable_type     = "mac32_bash_hash_table"
            nbuckets_offset = self.obj_vm.profile.get_obj_offset(htable_type, "nbuckets") 
        else:
            addr_type       = "unsigned long long"
            bucket_contents_type =  "mac64_bucket_contents"
            htable_type     = "mac64_bash_hash_table"
            nbuckets_offset = self.obj_vm.profile.get_obj_offset(htable_type, "nbuckets") 

        for map in self.get_proc_maps():
            if map.get_path() != "":
                continue

            off = map.start

            while off < map.end:
                # test the number of buckets
                dr = proc_as.read(off + nbuckets_offset, 4)
                if dr == None:
                    new_off = (off & ~0xfff) + 0xfff + 1
                    off = new_off
                    continue

                test = struct.unpack("<I", dr)[0]
                if test != 64:
                    off = off + 1
                    continue

                htable = obj.Object(htable_type, offset = off, vm = proc_as)
                
                if htable.is_valid():
                    bucket_array = obj.Object(theType="Array", targetType=addr_type, offset = htable.bucket_array, vm = htable.nbuckets.obj_vm, count = 64)

                    for bucket_ptr in bucket_array:
                        bucket = obj.Object(bucket_contents_type, offset = bucket_ptr, vm = htable.nbuckets.obj_vm)
                        while bucket != None and bucket.times_found > 0:  
                            pdata = bucket.data 

                            if pdata == None:
                                bucket = bucket.next_bucket()
                                continue

                            if pdata.is_valid() and (0 <= pdata.flags <= 2):
                                yield bucket

                            bucket = bucket.next_bucket()
                
                off = off + 1

    def bash_history_entries(self):
        proc_as = self.get_process_address_space()
            
        bit_string = str(self.task.map.pmap.pm_task_map or '')[9:]
        if bit_string.find("64BIT") == -1:
            pack_format = "<I"
            hist_struct = "bash32_hist_entry"
        else:
            pack_format = "<Q"
            hist_struct = "bash64_hist_entry"

        # Brute force the history list of an address isn't provided 
        ts_offset = proc_as.profile.get_obj_offset(hist_struct, "timestamp")

        history_entries = [] 
        bang_addrs = []

        # Look for strings that begin with pound/hash on the process heap 
        for ptr_hash in self.search_process_memory_rw_nofile(["#"]):                 
            # Find pointers to this strings address, also on the heap 
            addr = struct.pack(pack_format, ptr_hash)
            bang_addrs.append(addr)

        for (idx, ptr_string) in enumerate(self.search_process_memory_rw_nofile(bang_addrs)):
            # Check if we found a valid history entry object 
            hist = obj.Object(hist_struct, 
                              offset = ptr_string - ts_offset, 
                              vm = proc_as)

            if hist.is_valid():
                history_entries.append(hist)
    
        # Report everything we found in order
        for hist in sorted(history_entries, key = attrgetter('time_as_integer')):
            yield hist              

    def bash_environment(self):
        proc_as = self.get_process_address_space()
        
        # In cases when mm is an invalid pointer 
        if not proc_as:
            return
        
        procvars = []
        for mapping in self.get_proc_maps():
            if not str(mapping.get_perms()) == "rw-" or mapping.get_path().find("bash") == -1:
                continue

            env_start = 0
            for off in range(mapping.links.start, mapping.links.end):
                # check the first index
                addrstr = proc_as.read(off, self.pack_size)
                if not addrstr or len(addrstr) != self.pack_size:
                    continue
                addr = struct.unpack(self.pack_fmt, addrstr)[0]
                # check first idx...
                if addr:
                    firstaddrstr = proc_as.read(addr, self.pack_size)
                    if not firstaddrstr or len(firstaddrstr) != self.pack_size:
                        continue
                    firstaddr = struct.unpack(self.pack_fmt, firstaddrstr)[0]
                    buf = proc_as.read(firstaddr, 64)
                    if not buf:
                        continue
                    eqidx = buf.find("=")
                    if eqidx > 0:
                        nullidx = buf.find("\x00")
                        # single char name, =
                        if nullidx >= eqidx:
                            env_start = addr

            if env_start == 0:
                continue

            envars = obj.Object(theType="Array", targetType=self.addr_type, vm=proc_as, offset=env_start, count=256)
            for var in envars:
                if var:
                    sizes = [8, 16, 32, 64, 128, 256, 384, 512, 1024, 2048, 4096]
                    good_varstr = None

                    for size in sizes:
                        varstr = proc_as.read(var, size)
                        if not varstr:
                            continue

                        eqidx = varstr.find("=")
                        idx = varstr.find("\x00")

                        if idx == -1 or eqidx == -1 or idx < eqidx:
                            continue
                    
                        good_varstr = varstr
                        break
                
                    if good_varstr:        
                        good_varstr = good_varstr[:idx]
                        key = good_varstr[:eqidx]
                        val = good_varstr[eqidx+1:]

                        yield (key, val) 
                    else:
                        break         

    def netstat(self):
        for (filp, _, _) in self.lsof():
            if filp.f_fglob.fg_type == 'DTYPE_SOCKET':
                socket = filp.f_fglob.fg_data.dereference_as("socket") 
                family = socket.family
    
                if family == 1:
                    upcb = socket.so_pcb.dereference_as("unpcb")
                    path = upcb.unp_addr.sun_path
                    yield (family,  (socket.v(), path))
                elif family in [2, 30]:
                    proto = socket.protocol
                    state = socket.state
                   
                    (lip, lport, rip, rport) = socket.get_connection_info()
 
                    yield (family, (socket, proto, lip, lport, rip, rport, state))

    @property
    def p_gid(self):
        cred = self.p_ucred

        if not cred.is_valid():
            return -1

        if hasattr(cred, "cr_posix"):
            ret = cred.cr_posix.cr_groups[0]
        else:
            ret = cred.cr_groups[0]     
    
        return ret

    @property
    def p_uid(self):
        cred = self.p_ucred

        if not cred.is_valid():
            return -1 

        if hasattr(cred, "cr_posix"):
            ret = cred.cr_posix.cr_uid
        else:
            ret = cred.cr_uid     
        
        return ret

    def threads(self):
        threads = []
        seen_threads = []
        qentry = self.task.threads
        for thread in qentry.thread_walk_list(qentry.obj_offset):
            if thread.obj_offset not in seen_threads:
                seen_threads.append(thread.obj_offset)
                threads.append(thread)

        return threads 

    def get_process_address_space(self):
        cr3 = self.task.map.pmap.pm_cr3
        map_val = str(self.task.map.pmap.pm_task_map or '')

        # if the machine is 64 bit capable
        is_64bit_cap = common.is_64bit_capable(self.obj_vm)

        if map_val == "TASK_MAP_32BIT" and is_64bit_cap: 
            # A 32 bit process on a 64 bit system, requires 64 bit paging

            # Catch exceptions when trying to get a process AS for kernel_task
            # which isn't really even a process. It needs to use the default cr3
            try:
                proc_as = amd64.AMD64PagedMemory(self.obj_vm.base, 
                                                 self.obj_vm.get_config(), dtb = cr3, skip_as_check = True)
            except IOError:
                proc_as = self.obj_vm

        elif map_val == "TASK_MAP_32BIT":

            # A 32 bit process on a 32 bit system need 
            # bypass b/c no sharing of address space

            proc_as = intel.IA32PagedMemoryPae(self.obj_vm.base, 
                                                 self.obj_vm.get_config(), dtb = cr3, 
                                                 skip_as_check = True)

        elif (map_val == "TASK_MAP_64BIT_SHARED" and 
                    self.obj_vm.profile.metadata.get('memory_model', '32bit') == "32bit"):

            # A 64 bit process running on a 32 bit system
            proc_as = amd64.AMD64PagedMemory(self.obj_vm.base, 
                                             self.obj_vm.get_config(), dtb = cr3,
                                             skip_as_check = True)
            
        elif map_val in ["TASK_MAP_64BIT", "TASK_MAP_64BIT_SHARED"]:

            # A 64 bit process on a 64 bit system
            cr3 &= 0xFFFFFFE0
            proc_as = amd64.AMD64PagedMemory(self.obj_vm.base, 
                                             self.obj_vm.get_config(), dtb = cr3, 
                                             skip_as_check = True)
        else:
            proc_as = obj.NoneObject("Cannot get process AS for pm_task_map: {0}".format(map_val))

        return proc_as 

    def start_time(self):
        nsecs_per = 1000000
        
        start_time = self.p_start 
        start_secs = start_time.tv_sec + (start_time.tv_usec / nsecs_per)

        # convert the integer as little endian. we catch struct.error
        # here because if the process has exited (i.e. detected with mac_dead_procs)
        # then the timestamp may not be valid. start_secs could be negative
        # or higher than can fit in a 32-bit "I" integer field. 
        try:
            data = struct.pack("<I", start_secs)
        except struct.error:
            return ""

        bufferas = addrspace.BufferAddressSpace(self.obj_vm.get_config(), data = data)
        dt = obj.Object("UnixTimeStamp", offset = 0, vm = bufferas, is_utc = True)

        return dt
    
    def text_start(self):
        text_start = 0

        wanted_vnode = self.p_textvp.v()

        if wanted_vnode:
            for map in self.get_proc_maps():
                vnode = map.get_vnode()

                if vnode and vnode != "sub_map" and vnode.v() == wanted_vnode:
                    text_start = map.start.v()
                    break

        # both offset and vp were bogus
        if text_start == 0:
            found_map = None
            for map in self.get_dyld_maps():
                found_map = map
                break
        
            if found_map:
                text_start = found_map.imageLoadAddress

        return text_start

    def get_macho(self, exe_address):
        proc_as = self.get_process_address_space()

        m = obj.Object("macho_header", offset = exe_address, vm = proc_as)

        buffer = ""

        for seg in m.segments():
            if str(seg.segname) == "__PAGEZERO":
                continue
                
            # this is related to the shared cache map 
            # contact Andrew for full details
            if str(seg.segname) == "__LINKEDIT" and seg.vmsize > 20000000:
                continue

            cur = seg.vmaddr
            end = seg.vmaddr + seg.vmsize
        
            while cur < end:
                buffer = buffer + proc_as.zread(cur, 4096) 
                cur = cur + 4096
 
        return buffer

    def procdump(self):
        start = self.text_start()

        if start:
            ret = self.get_macho(start) 
        else:
            ret = ""

        return ret

    def get_dyld_maps(self):        
        proc_as = self.get_process_address_space()

        if self.pack_size == 4:
            dtype = "dyld32_all_image_infos"
            itype = "dyld32_image_info"
        else:
            dtype = "dyld64_all_image_infos"
            itype = "dyld64_image_info"

        infos = obj.Object(dtype, offset=self.task.all_image_info_addr, vm=proc_as)
        if not infos:
            return

        # the pointer address
        info_buf = proc_as.read(infos.infoArray.obj_offset, self.pack_size)
        if not info_buf:
            return

        info_addr = struct.unpack(self.pack_fmt, info_buf)[0] 

        img_infos = obj.Object(theType = "Array", targetType = itype, offset = info_addr, count = infos.infoArrayCount, vm = proc_as)
        
        for info_addr in img_infos:
            if info_addr:
                yield info_addr

    def get_proc_maps(self):
        map = self.task.map.hdr.links.next

        for i in xrange(self.task.map.hdr.nentries):
            if not map:
                break
            yield map
            map = map.links.next

    def find_heap_map(self):
        ret = None

        for pmap in self.get_proc_maps():
            if pmap.get_special_path() == "[heap]":
                ret = pmap
                break

        return None

    def find_map(self, addr):
        ret = None

        for vma in self.get_proc_maps():
            if int(vma.links.start) <= int(addr) <= int(vma.links.end):
                ret = vma
                break

        return ret

    def find_map_path(self, addr):
        path = ""
        m = self.find_map(addr)

        if m:
            path = m.get_path()
            if path == "":
                path = m.get_special_path()

        return path
              
    def search_process_memory(self, s):
        """Search process memory. 

        @param s: a list of strings like ["one", "two"]
        """

        # Allow for some overlap in case objects are 
        # right on page boundaries 
        overlap = 1024

        scan_blk_sz = 1024 * 1024 * 10
        addr_space = self.get_process_address_space()

        for vma in self.get_proc_maps():
            offset = vma.links.start
            out_of_range = vma.links.start + (vma.links.end - vma.links.start)
            while offset < out_of_range:
                # Read some data and match it.
                to_read = min(scan_blk_sz + overlap, out_of_range - offset)
                data = addr_space.zread(offset, to_read)
                if not data:
                    break
                for x in s:
                    for hit in utils.iterfind(data, x):
                        yield offset + hit
                offset += min(to_read, scan_blk_sz)


    def search_process_memory_rw_nofile(self, s):
        """Search process memory. 

        @param s: a list of strings like ["one", "two"]
        """

        # Allow for some overlap in case objects are 
        # right on page boundaries 
        overlap = 1024

        scan_blk_sz = 1024 * 1024 * 10
        addr_space = self.get_process_address_space()

        for vma in self.get_proc_maps():
            if vma.get_perms() != "rw-" or vma.get_path() != "":
                continue

            offset = vma.links.start
            out_of_range = vma.links.start + (vma.links.end - vma.links.start)
            while offset < out_of_range:
                # Read some data and match it.
                to_read = min(scan_blk_sz + overlap, out_of_range - offset)
                data = addr_space.zread(offset, to_read)
                if not data:
                    break
                for x in s:
                    for hit in utils.iterfind(data, x):
                        yield offset + hit
                offset += min(to_read, scan_blk_sz)

    def psenv(self):
        proc_as = self.get_process_address_space()

        # We need a valid process AS to continue 
        if not proc_as:
            return

        start = self.user_stack - self.p_argslen
        skip  = len(self.get_arguments())
        end   = self.p_argslen

        to_read = end - skip
    
        vars_buf = proc_as.read(start + skip, to_read)
        if vars_buf:
            ents = vars_buf.split("\x00")
            for varstr in ents:
                eqidx = varstr.find("=")

                if eqidx == -1:
                    continue

                key = varstr[:eqidx]
                val = varstr[eqidx+1:]

                yield (key, val) 
    
    def get_environment(self):
        env = ""

        for (k, v) in self.psenv():
            env = env + "{0}={1} ".format(k, v)

        return env

    def get_arguments(self):
        proc_as = self.get_process_address_space()

        # We need a valid process AS to continue 
        if not proc_as:
            return ""

        argsstart = self.user_stack - self.p_argslen

        # Stack location may be paged out or not contain any args
        if (not proc_as.is_valid_address(argsstart) or 
                self.p_argslen == 0 or self.p_argc == 0):
            return ""

        # Add one because the first two are usually duplicates
        argc = self.p_argc + 1
        args = []

        while argc > 0:
            arg = obj.Object("String", offset = argsstart, vm = proc_as, length = 256)
                
            if not arg:
                break

            # Initial address of the next string
            argsstart += len(str(arg)) + 1

            # Very first one is aligned in some crack ass way
            if len(args) == 0:
                while (proc_as.read(argsstart, 1) == "\x00" and 
                        argsstart < self.user_stack):
                    argsstart += 1
                args.append(arg)
            else:
                # Only add this string if its not a duplicate of the first
                if str(arg) != str(args[0]):
                    args.append(arg)
                            
            argc -= 1            

        return " ".join([str(s) for s in args])
    
    def lsof(self):
        num_fds = self.p_fd.fd_lastfile
        nfiles  = self.p_fd.fd_nfiles
        if nfiles > num_fds:
            num_fds = nfiles

        fds = obj.Object('Array', offset = self.p_fd.fd_ofiles, vm = self.obj_vm, targetType = 'Pointer', count = num_fds)

        for i, fd in enumerate(fds):
            f = fd.dereference_as("fileproc")
            if f:
                ftype = f.f_fglob.fg_type
                if ftype == 'DTYPE_VNODE': 
                    vnode = f.f_fglob.fg_data.dereference_as("vnode")
                    path = vnode.full_path()
                else:
                    path = ""
                        
                yield f, path, i

class rtentry(obj.CType):

    def get_time(self):
        if not hasattr(self, "base_calendartime"):
            return "N/A"

        data = struct.pack("<I", self.base_calendartime)
        bufferas = addrspace.BufferAddressSpace(self.obj_vm.get_config(), data = data)
        dt = obj.Object("UnixTimeStamp", offset = 0, vm = bufferas, is_utc = True) 

        return dt

    @property
    def sent(self):
        if hasattr(self, "rt_stats"):
            ret = self.rt_stats.nstat_txpackets
        else:
            ret = "N/A"

        return ret

    @property
    def rx(self):
        if hasattr(self, "rt_stats"):
            ret = self.rt_stats.nstat_rxpackets 
        else:
            ret = "N/A"

        return ret

    @property
    def delta(self):
        if self.expire() == 0:
            ret = 0
        else:
            ret = self.expire() - self.base_uptime

        return ret

    def expire(self):
        if hasattr(self, "rt_expire"):
            ret = self.rt_expire
        else:
            ret = 0

        return ret

    @property
    def name(self):
       return "{}{}".format(self.rt_ifp.if_name.dereference(), self.rt_ifp.if_unit)    
    
    @property
    def source_ip(self):
        return self.rt_nodes[0].rn_u.rn_leaf.rn_Key.dereference_as("sockaddr").get_address()

    @property
    def dest_ip(self):
        return self.rt_gateway.get_address()






 


    

class queue_entry(obj.CType):

    def walk_list(self, list_head):
        n = self.next.dereference_as("task")
        while n and n.obj_offset != list_head:
            yield n
            n = n.tasks.next.dereference_as("task")
        p = self.prev.dereference_as("task")
        while p and p.obj_offset != list_head:
            yield p
            p = p.tasks.prev.dereference_as("task")

class zone(obj.CType):
    def _get_from_active_zones(self):
        ret = []
        first_elem = self.active_zones
        elem = first_elem

        # TODO
        sz = 16

        i = 0

        while elem != first_elem.v() or i == 0:
            a = elem.v()
            b = sz
            off = a + b

            ret.append(off)
        
            i = i + 1
            if i == 4:
                break
            elem = elem.m("next")

        return ret

    def get_active_elements(self, elem_type, zone_idx=-1):
        ret = []

        if hasattr(self, "active_zones"):
            objs = self._get_from_active_zones()
        else:
            debug.error("zone does not have active zones.")        

        for o in objs:
            val = obj.Object(elem_type, offset = o, vm = self.obj_vm)
            ret.append(val)            

        return ret

    def get_free_elements(self, elem_type):
        ret = []

        nxt = obj.Object("zone_free_element", offset = self.free_elements, vm = self.obj_vm)

        while nxt:
            o = nxt.obj_offset

            val = obj.Object(elem_type, offset = o, vm = self.obj_vm)
            ret.append(val)
 
            nxt = nxt.m("next")
        
        return ret

class sysctl_oid(obj.CType):

    def get_perms(self):
        """
        # define CTLFLAG_RD      0x80000000      /* Allow reads of variable */
        # define CTLFLAG_WR      0x40000000      /* Allow writes to the variable */
        # define CTLFLAG_LOCKED  0x00800000      /* node will handle locking itself */
        """
        ret = ""

        checks = [0x80000000, 0x40000000, 0x00800000]
        perms  = ["R", "W", "L"]
        
        for (i, c) in enumerate(checks):
            if c & self.oid_kind:
                ret = ret + perms[i]
            else:
                ret = ret + "-"

        return ret

    def get_ctltype(self):
        """
        #define CTLTYPE_NODE    1
        #define CTLTYPE_INT     2       /* name describes an integer */
        #define CTLTYPE_STRING  3       /* name describes a string */
        #define CTLTYPE_QUAD    4       /* name describes a 64-bit number */
        #define CTLTYPE_OPAQUE  5       /* name describes a structure */
        #define CTLTYPE_STRUCT  CTLTYPE_OPAQUE  /* name describes a structure */
        """
            
        types = {1: 'CTLTYPE_NODE', 2: 'CTLTYPE_INT', 3: 'CTLTYPE_STRING', 4: 'CTLTYPE_QUAD', 5: 'CTLTYPE_OPAQUE'}
        ctltype = self.oid_kind & 0xf

        try:
            return types[ctltype]
        except KeyError:
            return "INVALID -1"

class OSString(obj.CType):
    def __str__(self):
        if self.string == 0:
            return ""

        string_object = obj.Object("String", offset = self.string, vm = self.obj_vm, length = self.length)
        return str(string_object or '')

class vm_map_entry(obj.CType):
    @property
    def start(self):
        return self.links.start

    @property
    def end(self):
        return self.links.end

    def get_perms(self):
        permask = "rwx"
        perms = ""

        for (ctr, i) in enumerate([1, 3, 5]):
            if (self.protection & i) == i:
                perms = perms + permask[ctr]
            else:
                perms = perms + "-"

        return perms


    # used to find heap, stack, etc.
    def get_special_path(self):
        # check the heap
        ret = ""

        for i in [1, 2, 3, 4, 6, 7, 8, 9]:
            if self.alias == i:
                ret = "[heap]"
                break

        if ret != "":
            return ret

        if self.alias == 30:
            ret = "[stack]"

        return ret 

    def get_path(self):
        vnode = self.get_vnode()
    
        if type(vnode) == str and vnode == "sub_map":
            ret = vnode  
        elif vnode:
            path = []
            while vnode:
                path.append(str(vnode.v_name.dereference() or ''))
                vnode = vnode.v_parent
            path.reverse()
            ret = "/".join(path)
        else:
            ret = ""
                
        return ret

    def get_vnode(self):
        map_obj = self

        if self.is_sub_map == 1:
            return "sub_map"

        # find_vnode_object
        vnode_object = map_obj.object.vm_object 

        while vnode_object.shadow.dereference() != None:
            vnode_object = vnode_object.shadow.dereference()

        ops = vnode_object.pager.mo_pager_ops.v()

        if ops == self.obj_vm.profile.get_symbol("_vnode_pager_ops"):
            vpager = obj.Object("vnode_pager", offset = vnode_object.pager, vm = self.obj_vm)
            ret = vpager.vnode_handle
        else:
            ret = None

        return ret

    def is_suspicious(self):
        ret = False        

        perms = self.get_perms()

        if perms == "rwx":
           ret = True 

        elif perms == "r-x" and self.get_path() == "":
            ret = True
 
        return ret


class inpcb(obj.CType):
    
    def get_tcp_state(self):
        tcp_states = (
              "CLOSED",
              "LISTEN",
              "SYN_SENT",
              "SYN_RECV",
              "ESTABLISHED",
              "CLOSE_WAIT",
              "FIN_WAIT1",
              "CLOSING",
              "LAST_ACK",
              "FIN_WAIT2",
              "TIME_WAIT")

        tcpcb = self.inp_ppcb.dereference_as("tcpcb")

        state_type = tcpcb.t_state
        if state_type:
            state = tcp_states[state_type]
        else:
            state = ""

        return state

    def ipv4_info(self):
        lip = self.inp_dependladdr.inp46_local.ia46_addr4.s_addr.v()    
        lport = self.inp_lport 

        rip = self.inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr.v()
        rport = self.inp_fport 
    
        return [lip, lport, rip, rport]

    def ipv6_info(self):
        lip = self.inp_dependladdr.inp6_local.__u6_addr.v()
        lport = self.inp_lport 

        rip = self.inp_dependfaddr.inp6_foreign.__u6_addr.v() 
        rport = self.inp_fport 

        return [lip, lport, rip, rport]

class inpcbinfo(obj.CType):
    @property
    def hashbase(self):
        ret = self.members.get("hashbase")
        if ret is None:
            ret = self.ipi_hashbase
        else:
            ret = self.m("hashbase")

        return ret

    @property
    def hashmask(self):
        ret = self.members.get("hashmask")
        if ret is None:
            ret = self.ipi_hashmask
        else:
            ret = self.m("hashmask")

        return ret

    @property
    def listhead(self):
        ret = self.members.get("listhead")
        if ret is None:
            ret = self.ipi_listhead
        else:
            ret = self.m("listhead")

        return ret


class socket(obj.CType):
    @property
    def family(self):
        return self.so_proto.pr_domain.dom_family

    @property
    def protocol(self):
        proto = self.so_proto.pr_protocol
       
        if proto == 6:
            ret = "TCP"
        elif proto == 17:
            ret = "UDP"
        else:
            ret = ""             
 
        return ret

    def _get_tcp_state(self):
        tcp_states = (
              "CLOSED",
              "LISTEN",
              "SYN_SENT",
              "SYN_RECV",
              "ESTABLISHED",
              "CLOSE_WAIT",
              "FIN_WAIT1",
              "CLOSING",
              "LAST_ACK",
              "FIN_WAIT2",
              "TIME_WAIT")

        inpcb = self.so_pcb.dereference_as("inpcb")
        tcpcb = inpcb.inp_ppcb.dereference_as("tcpcb")

        return tcp_states[tcpcb.t_state]

    @property
    def state(self):
        if self.so_proto.pr_protocol == 6:
            ret = self._get_tcp_state()
        else:
            ret = ""
        
        return ret
        
    def get_connection_info(self):
        ipcb = self.so_pcb.dereference_as("inpcb")
        
        if self.family == 2:
            ret = ipcb.ipv4_info()
        else:
            ret = ipcb.ipv6_info()

        return ret

class sockaddr_dl(obj.CType):
    def v(self):
        """Get the value of the sockaddr_dl object."""

        ret = ""
        for i in xrange(self.sdl_alen):
            try:
                e = self.sdl_data[self.sdl_nlen + i]
                e = ord(e.v())
            except IndexError:
                e = 0
            ret = ret + "%.02x:" % e
    
        if ret and ret[-1] == ":":
            ret = ret[:-1]

        return ret

class sockaddr(obj.CType):
    def get_address(self):
        family = self.sa_family

        ip = ""

        if family == 2: # AF_INET
            addr_in = obj.Object("sockaddr_in", offset = self.obj_offset, vm = self.obj_vm) 
            ip = addr_in.sin_addr.s_addr.v()

        elif family == 30: # AF_INET6
            addr_in6 = obj.Object("sockaddr_in6", offset = self.obj_offset, vm = self.obj_vm) 
            ip = addr_in6.sin6_addr.__u6_addr.v()

        elif family == 18: # AF_LINK
            addr_dl = obj.Object("sockaddr_dl", offset = self.obj_offset, vm = self.obj_vm) 
            ip = addr_dl.v()

        return ip

class dyld32_image_info(obj.CType):
    def _read_ptr(self, addr):
        addr = self.obj_vm.read(addr, 4)
        if not addr:
            ret = None
        else:
            ret = struct.unpack("<I", addr)[0]         
        return ret

    @property
    def imageFilePath(self):
        addr = self.m("imageFilePath").obj_offset
        addr = self._read_ptr(addr)
        
        if addr == None:
            return ""

        buf = self.obj_vm.read(addr, 256)
        if buf:
            idx = buf.find("\x00")
            if idx != -1:
                buf = buf[:idx]

        return buf

    @property
    def imageLoadAddress(self):
        addr = self.m("imageLoadAddress").obj_offset
        addr = self._read_ptr(addr)
                 
        return addr

class dyld64_image_info(obj.CType):
    def _read_ptr(self, addr):
        addr = self.obj_vm.read(addr, 8)
        if addr == None:
            ret = None
        else:
            ret = struct.unpack("<Q", addr)[0]         
        return ret

    @property
    def imageFilePath(self):
        addr = self.m("imageFilePath").obj_offset
        addr = self._read_ptr(addr)

        if addr == None:
            return ""

        buf = self.obj_vm.read(addr, 256)
        if buf:
            idx = buf.find("\x00")
            if idx != -1:
                buf = buf[:idx]

        return buf

    @property
    def imageLoadAddress(self):
        addr = self.m("imageLoadAddress").obj_offset
        addr = self._read_ptr(addr)
                 
        return addr

def exec_vtypes(filename):
    env = {}
    exec(filename, dict(__builtins__ = None), env)
    return env["mac_types"]

def parse_dsymutil(data, module):
    """Parse the symbol file."""
    sys_map = {}
    sys_map[module] = {}

    want_lower = ["_IdlePML4"]        

    type_map = {}
    type_map[module] = {}

    arch = ""

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

        elif line.find("Symbol table for") != -1:
            if line.find("i386") != -1:
                arch = "32bit"
            else:
                arch = "64bit"

    if arch == "":
        return None

    return arch, sys_map, type_map

def MacProfileFactory(profpkg):

    vtypesvar = {}
    sysmapvar = {}
    typesmapvar = {}

    memmodel, arch = "32bit", "x86"
    profilename = os.path.splitext(os.path.basename(profpkg.filename))[0]
 
    for f in profpkg.filelist:
        if 'symbol.dsymutil' in f.filename.lower():
            memmodel, sysmap, typemap = parse_dsymutil(profpkg.read(f.filename), "kernel")
            if memmodel == "64bit":
                arch = "x64"
            
            sysmapvar.update(sysmap)
            typesmapvar.update(typemap)
            debug.debug("{2}: Found system file {0} with {1} symbols".format(f.filename, len(sysmapvar.keys()), profilename))

        elif f.filename.endswith(".vtypes"):
            v = exec_vtypes(profpkg.read(f.filename))                       
            vtypesvar.update(v)

    if not sysmapvar or not vtypesvar:
        # Might be worth throwing an exception here?
        return None

    class AbstractMacProfile(obj.Profile):
        __doc__ = "A Profile for Mac " + profilename + " " + arch
        _md_os = "mac"
        _md_memory_model = memmodel

        native_mapping = {'32bit': native_types.x86_native_types,
                          '64bit': x64_native_types}


        def __init__(self, *args, **kwargs):
            self._init_vars()
            obj.Profile.__init__(self, *args, **kwargs)

        def _init_vars(self):
            self.sys_map = {}
            self.type_map = {}
            self.shift_address = 0
            self.sba_cache = {}
            self.sbat_cache = {}
            
        def clear(self):
            """Clear out the system map, and everything else"""
            self._init_vars() 
            obj.Profile.clear(self)

        def reset(self):
            """Reset the vtypes, sysmap and apply modifications, then compile"""
            self.clear()
            self.load_vtypes()
            self.load_sysmap()
            self.load_modifications()
            self.compile()

        def load_vtypes(self):
            """Loads up the vtypes data"""
            ntvar = self.metadata.get('memory_model', '32bit')
            self.native_types = copy.deepcopy(self.native_mapping.get(ntvar))

            self.vtypes.update(vtypesvar)

        def load_sysmap(self):
            """Loads up the system map data"""
            self.sys_map.update(sysmapvar)
            self.type_map.update(typesmapvar)

        # Returns a list of (name, addr)
        def get_all_symbols(self, module = "kernel"):
            """ Gets all the symbol tuples for the given module """
            ret = []

            symtable = self.sys_map

            if module in symtable:
                mod = symtable[module]

                for (name, addrs) in mod.items():
                    addr = addrs[0][0]
                    if self.shift_address and addr:
                        addr = addr + self.shift_address

                    ret.append([name, addr])
            else:
                debug.info("All symbols requested for non-existent module %s" % module)

            return ret

        def get_all_addresses(self, module = "kernel"):
            """ Gets all the symbol addresses for the given module """
            # returns a hash table for quick looks
            # the main use of this function is to see if an address is known
            ret = {}

            symbols = self.get_all_symbols(module)

            for (_name, addr) in symbols:
                ret[addr] = 1

            return ret

        ############################################

        # Returns a list of (name, addr)
        def get_all_function_symbols(self, module = "kernel"):
            """ Gets all the function tuples for the given module """
            ret = []

            symtable = self.type_map

            if module in symtable:
                mod = symtable[module]

                for (addr, (name, _sym_types)) in mod.items():
                    if self.shift_address and addr:
                        addr = addr + self.shift_address

                    ret.append([name, addr])
            else:
                debug.info("All symbols requested for non-existent module %s" % module)

            return ret

        def get_all_function_addresses(self, module = "kernel"):
            """ Gets all the function addresses for the given module """
            # returns a hash table for quick looks
            # the main use of this function is to see if an address is known
            ret = {}

            symbols = self.get_all_function_symbols(module)

            for (_name, addr) in symbols:
                ret[addr] = 1

            return ret

        def _get_symbol_by_address_type(self, module, wanted_sym_address, wanted_sym_type):
            ret = ""
            
            symtable = self.type_map

            mod = symtable[module]

            for (addr, (name, sym_types)) in mod.items():
                for sym_type in sym_types:
                    key = "%s|%x|%s" % (module, addr, sym_type)
                    self.sbat_cache[key] = name

                    if (wanted_sym_address == addr or wanted_sym_address == self.shift_address + addr) and wanted_sym_type == sym_type:
                        ret = name
                        break
 
            return ret
        
        def get_symbol_by_address_type(self, module, sym_address, sym_type):
            key = "%s|%x|%s" % (module, sym_address, sym_type)
            if key in self.sbat_cache:
                ret = self.sbat_cache[key]
            else:
                ret = self._get_symbol_by_address_type(module, sym_address, sym_type)
            
            return ret

        def _fill_sba_cache(self):
            ret = ""
            
            symtable = self.sys_map
            mod = symtable["kernel"]

            for (name, addrs) in mod.items():
                for (addr, _) in addrs:
                    key = "%s|%x" % ("kernel", addr)
                    self.sba_cache[key] = name

                    key = "%s|%x" % ("kernel", addr + self.shift_address)
                    self.sba_cache[key] = name
        
        def get_symbol_by_address(self, module, sym_address):
            if self.sba_cache == {}:
                self._fill_sba_cache()
    
            key = "%s|%x" % (module, sym_address)
            if key in self.sba_cache:
                ret = self.sba_cache[key]
            else:
                ret = ""
 
            return ret

        def get_all_symbol_names(self, module = "kernel"):
            symtable = self.sys_map

            if module in symtable:
                ret = symtable[module].keys()
            else:
                debug.error("get_all_symbol_names called on non-existent module")

            return ret

        def get_next_symbol_address(self, sym_name, module = "kernel"):
            """
            This is used to find the address of the next symbol in the profile
            For some data structures, we cannot determine their size automaticlaly so this
            can be used to figure it out on the fly
            """

            high_addr = 0xffffffffffffffff
            table_addr = self.get_symbol(sym_name, module = module)

            addrs = self.get_all_addresses(module = module)

            for addr in addrs.keys():

                if table_addr < addr < high_addr:
                    high_addr = addr

            return high_addr

        def get_symbol(self, sym_name, nm_type = "", module = "kernel"):
            """Gets a symbol out of the profile
            
            sym_name -> name of the symbol
            nm_tyes  -> types as defined by 'nm' (man nm for examples)
            module   -> which module to get the symbol from, default is kernel, otherwise can be any name seen in 'lsmod'
    
            This fixes a few issues from the old static hash table method:
            1) Conflicting symbols can be handled, if a symbol is found to conflict on any profile, 
               then the plugin will need to provide the nm_type to differentiate, otherwise the plugin will be errored out
            2) Can handle symbols gathered from modules on disk as well from the static kernel
    
            symtable is stored as a hash table of:
            
            symtable[module][sym_name] = [(symbol address, symbol type), (symbol addres, symbol type), ...]
    
            The function has overly verbose error checking on purpose...
            """

            symtable = self.sys_map

            ret = None

            # check if the module is there...
            if module in symtable:

                mod = symtable[module]

                # check if the requested symbol is in the module
                if sym_name in mod:

                    sym_list = mod[sym_name]

                    # if a symbol has multiple definitions, then the plugin needs to specify the type
                    if len(sym_list) > 1:
                        if nm_type == "":
                            debug.error("Requested symbol {0:s} in module {1:s} has multiple definitions and no type given\n".format(sym_name, module))
                        else:
                            for (addr, stype) in sym_list:

                                if stype == nm_type:
                                    ret = addr
                                    break

                            if ret == None:
                                debug.error("Requested symbol {0:s} in module {1:s} could not be found\n".format(sym_name, module))
                    else:
                        # get the address of the symbol
                        ret = sym_list[0][0]
                else:
                    debug.debug("Requested symbol {0:s} not found in module {1:s}\n".format(sym_name, module))
            else:
                debug.info("Requested module {0:s} not found in symbol table\n".format(module))

            if self.shift_address and ret:
                ret = ret + self.shift_address

            return ret

    cls = AbstractMacProfile
    cls.__name__ = 'Mac' + profilename.replace('.', '_') + arch

    return cls

################################
# Track down the zip files
# Push them through the factory
# Check whether ProfileModifications will work

new_classes = []

for path in set(plugins.__path__):
    for path, _, files in os.walk(path):
        for fn in files:
            if zipfile.is_zipfile(os.path.join(path, fn)):
                new_classes.append(MacProfileFactory(zipfile.ZipFile(os.path.join(path, fn))))

class MacOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'mac'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.merge_overlay(mac_overlay)

class MacObjectClasses(obj.ProfileModification):

    conditions = {'os': lambda x: x == 'mac'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.object_classes.update({
            'VolatilityDTB': VolatilityDTB,
            'VolatilityMacIntelValidAS' : VolatilityMacIntelValidAS,
            'proc'  : proc,
            'thread'  : thread,
            'kauth_scope'  : kauth_scope,
            'dyld32_image_info' : dyld32_image_info,
            'dyld64_image_info' : dyld64_image_info,
            'fileglob' : fileglob,
            'vnode' : vnode,
            'ifnet' : ifnet,
            'socket' : socket,
            'inpcbinfo' : inpcbinfo,
            'inpcb' : inpcb,
            'zone' : zone,
            'OSString' : OSString,
            'OSString_class' : OSString,
            'sysctl_oid' : sysctl_oid,
            'IpAddress': basic.IpAddress,
            'Ipv6Address': basic.Ipv6Address,
            'sockaddr' : sockaddr, 
            'sockaddr_dl' : sockaddr_dl,
            'vm_map_entry' : vm_map_entry,
            'rtentry' : rtentry,
            'queue_entry' : queue_entry,
        })

mac_overlay = {
    'VOLATILITY_MAGIC': [None, {
        'DTB'           : [ 0x0, ['VolatilityDTB', dict(configname = "DTB")]],
        'IA32ValidAS'   : [ 0x0, ['VolatilityMacIntelValidAS']],
        'AMD64ValidAS'  : [ 0x0, ['VolatilityMacIntelValidAS']],
        }],

    'session' : [ None, {
        's_login' : [ None , ['String', dict(length = 256)]],
        }],
    'kfs_event' : [ None, {
        'str' : [ None, ['pointer', ['String', dict(length = 256)]]], 
        }], 
    'zone' : [ None, {
        'zone_name': [ None, ['pointer', ['String', dict(length = 256)]]],
        }],
    'mac_policy_conf' : [ None, { 
        'mpc_name' : [ None, ['pointer', ['String', dict(length = 256)]]], 
        }], 
    'proc' : [ None, { 
        'p_comm' : [ None, ['String', dict(length = 17)]], 
        'task' : [ None, ['pointer', ['task']]], 
        }], 
    'ifnet' : [ None, { 
        'if_name' : [ None, ['pointer', ['String', dict(length = 256)]]], 
        }], 
    'vnode' : [ None, {
        'v_name' : [ None, ['pointer', ['String', dict(length = 256)]]], 
        }], 
    'boot_args' : [ None, {
        'CommandLine' : [ None, ['String', dict(length = 1024)]],
        }], 
    'vfsstatfs' : [ None, { 
        'f_fstypename' : [ None, ['String', dict(length = 16)]],
        'f_mntonname' : [ None, ['String', dict(length = 1024)]],
        'f_mntfromname' : [ None, ['String', dict(length = 1024)]],
        }], 
    'kmod_info' : [ None, { 
        'name' : [ None, ['String', dict(length = 64)]],
        'version' : [ None, ['String', dict(length = 64)]],
        }], 
    'ipf_filter' : [ None, { 
        'name' : [ None, ['pointer', ['String', dict(length = 256)]]], 
        }], 
    'sysctl_oid' : [ None, { 
        'oid_name' : [ None, ['pointer', ['String', dict(length = 256)]]], 
        }], 
    'dyld32_image_info' : [ None, { 
        'imageFilePath' : [ None, ['pointer', ['String', dict(length = 256)]]], 
        }], 
    'dyld64_image_info' : [ None, { 
        'imageFilePath' : [ None, ['pointer', ['String', dict(length = 256)]]], 
        }], 
    'sockaddr_un': [ None, { 
        'sun_path' : [ None, ['String', dict(length = 104)]],
        }],
    'in_addr' : [ None, { 
        's_addr' : [ None, ['IpAddress']], 
        }], 
    'in6_addr' : [ None, {
        '__u6_addr' : [ None, ['Ipv6Address']], 
        }], 
    'inpcb' : [ None, { 
        'inp_lport' : [ None, ['unsigned be short']], 
        'inp_fport' : [ None, ['unsigned be short']], 
        }], 
}


