# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie@memoryanalysis.net>
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
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie@memoryanalysis.net
@organization: Volatility Foundation
"""

import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.taskmods as taskmods
import volatility.plugins.registry.shimcache as shimcache
import volatility.plugins.filescan as filescan
import volatility.plugins.sockets as sockets
import volatility.plugins.sockscan as sockscan
import volatility.plugins.modscan as modscan
import volatility.plugins.moddump as moddump
import volatility.plugins.netscan as netscan
import volatility.plugins.evtlogs as evtlogs
import volatility.plugins.malware.psxview as psxview
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.malware.timers as timers
import volatility.plugins.registry.userassist as userassist
import volatility.plugins.imageinfo as imageinfo
import volatility.win32.rawreg as rawreg
import volatility.addrspace as addrspace
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.protos as protos
import volatility.plugins.iehistory as iehistory
import os, sys, ntpath
import struct
import volatility.debug as debug
import volatility.obj as obj 
import datetime
from volatility.renderers import TreeGrid

class Win7LdrDataTableEntry(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 1}

    def modification(self, profile):
        overlay = {'_LDR_DATA_TABLE_ENTRY': [ None, {
                        'LoadTime' : [ None, ['WinTimeStamp', dict(is_utc = True)]],
                                        }],
                   # these timestamps need more research for format
                   #'_MMSUPPORT': [ None, {
                   #     'LastTrimStamp': [ None, ['None', dict(is_utc = True)]],
                   #                     }],
                   #'_MMPTE_TIMESTAMP': [ None, {
                   #     'GlobalTimeStamp' : [ None, ['None', dict(is_utc = True)]],
                   #                     }],
                   } 
        profile.merge_overlay(overlay)

class Win7SP1CMHIVE(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x >= 1,
                  'build': lambda x: x >= 7601}

    def modification(self, profile):
        overlay = {'_CMHIVE': [ None, {
                        'LastWriteTime' : [ None, ['WinTimeStamp', dict(is_utc = True)]],
                                        }]}
        profile.merge_overlay(overlay)

class WinXPTrim(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                 }

    def modification(self, profile):
        overlay = {'_MMSUPPORT': [ None, {
                        'LastTrimTime': [ None, ['WinTimeStamp', dict(is_utc = True)]],
                                        }],
                  }
                                        
        profile.merge_overlay(overlay)

class WinAllTime(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',}

    def modification(self, profile):
        overlay = {'_HBASE_BLOCK': [ None, {
                        'TimeStamp' : [ None, ['WinTimeStamp', dict(is_utc = True)]],
                                        }],
                   '_CM_KEY_CONTROL_BLOCK': [ None, {
                        'KcbLastWriteTime': [ None, ['WinTimeStamp', dict(is_utc = True)]],
                                        }],
                   '_IMAGE_DEBUG_DIRECTORY': [ None, {
                        'TimeDateStamp': [ None, ['UnixTimeStamp', dict(is_utc = True)]],
                                        }],
                  } 
        profile.merge_overlay(overlay)

class TimeLiner(common.AbstractWindowsCommand):
    """ Creates a timeline from various artifacts in memory """

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.remove_option("SAVE-EVT")
        config.remove_option("HIVE-OFFSET")
        config.remove_option("KEY")
        config.remove_option("BASE")
        config.remove_option("REGEX")
        config.remove_option("IGNORE-CASE")
        config.remove_option("DUMP-DIR")
        config.remove_option("OFFSET")
        config.remove_option("PID")
        config.remove_option("UNSAFE")

        self.types = ["Process", "Socket", "Shimcache", "Userassist", "IEHistory", "Thread", "Symlink", "Timer",
                      "_CM_KEY_BODY", "LoadTime", "TimeDateStamp", "_HBASE_BLOCK", "_CMHIVE", "EvtLog", "ImageDate"]

        config.add_option('HIVE', short_option = 'H',
                          help = 'Gather Timestamps from a Particular Registry Hive', type = 'str')
        config.add_option('USER', short_option = 'U',
                          help = 'Gather Timestamps from a Particular User\'s Hive(s)', type = 'str')
        config.add_option("MACHINE", default = "",
                        help = "Machine name to add to timeline header")
        config.add_option("TYPE", default = "".join([",".join(x for x in sorted(self.types))]),
                        help = "Type of artifact to use in timeline (default is all, but \"Registry\")")


    def unified_output(self, data):
        return TreeGrid([("Start", str),
                       ("Header", str),
                       ("Item", str),
                       ("Details", str)],
                        self.generator(data))

    def generator(self, data):
        for line in data:
            yield (0, line.split("|"))

    # leaving render_text in for now
    def render_text(self, outfd, data):
        for line in data:
            if line != None:
                outfd.write("{0}\n".format(line))
    
    def render_body(self, outfd, data):
        for line in data:
            if line != None:
                outfd.write(line) 

    def getoutput(self, header, start, end = None, body = False):
        if body:
            try:
                if end == None:
                    return "0|{0}|0|---------------|0|0|0|{1}|{1}|{1}|{1}\n".format(header, start.v())
                else:
                    return "0|{0}|0|---------------|0|0|0|{1}|{2}|{1}|{1}\n".format(header, start.v(), end.v())
            except ValueError, ve:
                return "0|{0}|0|---------------|0|0|0|{1}|{1}|{1}|{1}\n".format(header, 0)
        else:
            try:
                if end == None or end.v() == 0:
                    return "{0}|{1}".format(start, header)
                else:
                    return "{0}|{1} End: {2}".format(start, header, end)
            except ValueError, ve:
                return "{0}|{1}".format(-1, header)
                
    def calculate(self):
        if (self._config.HIVE or self._config.USER) and "Registry" not in self._config.TYPE:
            debug.error("You must use --registry in conjuction with -H/--hive and/or -U/--user")
        if self._config.TYPE != None:
            for t in self._config.TYPE.split(","):
                if t.strip() not in self.types and t.strip() != "Registry":
                    debug.error("You have entered an incorrect type: {0}".format(t))

        addr_space = utils.load_as(self._config)
        version = (addr_space.profile.metadata.get('major', 0), 
                   addr_space.profile.metadata.get('minor', 0))

        pids = {}     #dictionary of process IDs/ImageFileName
        
        body = False
        if self._config.OUTPUT == "body":
            body = True
        if self._config.MACHINE != "":
            self._config.update("MACHINE", "{0} ".format(self._config.MACHINE))

        if "ImageDate" in self._config.TYPE:
            im = imageinfo.ImageInfo(self._config).get_image_time(addr_space)
            yield self.getoutput("[{0}LIVE RESPONSE]{1} (System time){1}".format(
                self._config.MACHINE, "" if body else "|"), 
                im['ImageDatetime'], body = body)

        if version <= (6, 1) and "IEHistory" in self._config.TYPE:
            self._config.update("LEAK", True)
            data = iehistory.IEHistory(self._config).calculate()
            for process, record in data:
                ## Extended fields are available for these records 
                if record.obj_name == "_URL_RECORD":
                    line = "[{6}IEHISTORY]{0} {1}->{5}{0} PID: {2}/Cache type \"{3}\" at {4:#x}".format(
                        "" if body else "|",
                        process.ImageFileName,
                        process.UniqueProcessId,
                        record.Signature, record.obj_offset,
                        record.Url,
                        self._config.MACHINE)
                        
                    yield self.getoutput(line, record.LastModified, end = record.LastAccessed, body = body)
            self._config.remove_option("REDR")
            self._config.remove_option("LEAK")

        psx = []
        if "Process" in self._config.Type or "TimeDateStamp" in self._config.Type or \
            "LoadTime" in self._config.Type or "_CM_KEY_BODY" in self._config.Type:
            psx = psxview.PsXview(self._config).calculate()
        for offset, eprocess, ps_sources in psx:
            pids[eprocess.UniqueProcessId.v()] = eprocess.ImageFileName
            if "Process" in self._config.TYPE:
                line = "[{5}PROCESS]{0} {1}{0} PID: {2}/PPID: {3}/POffset: 0x{4:08x}".format(
                    "" if body else "|",
                    eprocess.ImageFileName,
                    eprocess.UniqueProcessId,
                    eprocess.InheritedFromUniqueProcessId,
                    offset,
                    self._config.MACHINE)

                yield self.getoutput(line, eprocess.CreateTime, end = eprocess.ExitTime, body = body)

            if not hasattr(eprocess.obj_vm, "vtop"):
                eprocess = taskmods.DllList(self._config).virtual_process_from_physical_offset(addr_space, eprocess.obj_offset)
                if eprocess == None:
                    continue
            else:
                ps_ad = eprocess.get_process_address_space()
                if ps_ad == None:
                    continue
                
            if version[0] == 5 and "Process" in self._config.TYPE:
                line = "[{5}PROCESS LastTrimTime]{0} {1}{0} PID: {2}/PPID: {3}/POffset: 0x{4:08x}".format(
                    "" if body else "|",
                    eprocess.ImageFileName,
                    eprocess.UniqueProcessId,
                    eprocess.InheritedFromUniqueProcessId,
                    offset,
                    self._config.MACHINE)
                yield self.getoutput(line, eprocess.Vm.LastTrimTime, body = body)

            if eprocess.ObjectTable.HandleTableList and "_CM_KEY_BODY" in self._config.TYPE:
                for handle in eprocess.ObjectTable.handles():
                    if not handle.is_valid():
                        continue

                    name = ""
                    object_type = handle.get_object_type()
                    if object_type == "Key":
                        key_obj = handle.dereference_as("_CM_KEY_BODY")
                        name = key_obj.full_key_name()
                        line = "[{6}Handle (Key)]{0} {1}{0} {2} PID: {3}/PPID: {4}/POffset: 0x{5:08x}".format(
                            "" if body else "|",
                            name,
                            eprocess.ImageFileName,
                            eprocess.UniqueProcessId,
                            eprocess.InheritedFromUniqueProcessId,
                            offset,
                            self._config.MACHINE)
                        yield self.getoutput(line, key_obj.KeyControlBlock.KcbLastWriteTime, body = body)


            if eprocess.Peb == None or eprocess.Peb.ImageBaseAddress == None:
                continue
            # Get DLL PE timestamps for Wow64 processes (excluding 64-bit ones)
            if eprocess.IsWow64 and "TimeDateStamp" in self._config.TYPE:
                for vad, address_space in eprocess.get_vads(vad_filter = eprocess._mapped_file_filter):
                    if vad.FileObject.FileName:
                        name = str(vad.FileObject.FileName).lower()
                        basename = ntpath.basename(name)
                        if not basename.endswith("dll") or basename in ["wow64cpu.dll", "ntdll.dll", "wow64.dll", "wow64win.dll"]:
                            continue
                        data = ps_ad.zread(vad.Start, vad.Length)
                        bufferas = addrspace.BufferAddressSpace(self._config, data = data)
                        try:
                            pe_file = obj.Object("_IMAGE_DOS_HEADER", offset = 0, vm = bufferas)
                            header = pe_file.get_nt_header()
                        except ValueError, ve: 
                            continue
                        line = "[{7}PE HEADER 32-bit (dll)]{0} {4}{0} Process: {1}/PID: {2}/PPID: {3}/Process POffset: 0x{5:08x}/DLL Base: 0x{6:08x}".format(
                            "" if body else "|",
                            eprocess.ImageFileName,
                            eprocess.UniqueProcessId,
                            eprocess.InheritedFromUniqueProcessId,
                            basename,
                            offset,
                            vad.Start,
                            self._config.MACHINE)
                        yield self.getoutput(line, header.FileHeader.TimeDateStamp, body = body)

            # get DLL PE timestamps
            mods = dict()
            if "TimeDateStamp" in self._config.TYPE or "LoadTime" in self._config.TYPE:
                mods = dict((mod.DllBase.v(), mod) for mod in eprocess.get_load_modules())
            for mod in mods.values():
                basename = str(mod.BaseDllName or "")
                if basename == str(eprocess.ImageFileName):
                    line = "[{7}PE HEADER (exe)]{0} {4}{0} Process: {1}/PID: {2}/PPID: {3}/Process POffset: 0x{5:08x}/DLL Base: 0x{6:08x}".format(
                        "" if body else "|",
                        eprocess.ImageFileName,
                        eprocess.UniqueProcessId,
                        eprocess.InheritedFromUniqueProcessId,
                        basename,
                        offset,
                        mod.DllBase.v(),
                        self._config.MACHINE)
                else:
                    line = "[{7}PE HEADER (dll)]{0} {4}{0} Process: {1}/PID: {2}/PPID: {3}/Process POffset: 0x{5:08x}/DLL Base: 0x{6:08x}".format(
                        "" if body else "|",
                        eprocess.ImageFileName,
                        eprocess.UniqueProcessId,
                        eprocess.InheritedFromUniqueProcessId,
                        basename,
                        offset,
                        mod.DllBase.v(),
                        self._config.MACHINE)
                if "TimeDateStamp" in self._config.TYPE:
                    yield self.getoutput(line, mod.TimeDateStamp, body = body)
                    line2 = "[{7}PE DEBUG]{0} {4}{0} Process: {1}/PID: {2}/PPID: {3}/Process POffset: 0x{5:08x}/DLL Base: 0x{6:08x}".format(
                        "" if body else "|",
                        eprocess.ImageFileName,
                        eprocess.UniqueProcessId,
                        eprocess.InheritedFromUniqueProcessId,
                        basename,
                        offset,
                        mod.DllBase.v(),
                        self._config.MACHINE)
                    yield self.getoutput(line2, mod.get_debug_directory().TimeDateStamp, body = body)
                if hasattr(mod, "LoadTime") and "LoadTime" in self._config.TYPE:
                    temp = line.replace("[{0}PE HEADER ".format(self._config.MACHINE), "[{0}DLL LOADTIME ".format(self._config.MACHINE))
                    yield self.getoutput(temp, mod.LoadTime, body = body)

        # Get Sockets and Evtlogs XP/2k3 only
        if version[0] == 5:
            #socks = sockets.Sockets(self._config).calculate()
            socks = []
            if "Socket" in self._config.TYPE:
                socks = sockscan.SockScan(self._config).calculate()   # you can use sockscan instead if you uncomment
            for sock in socks:
                la = "{0}:{1}".format(sock.LocalIpAddress, sock.LocalPort)
                line = "[{6}SOCKET]{0} LocalIP: {2}/Protocol: {3}({4}){0} PID: {1}/POffset: 0x{5:#010x}".format(
                        "" if body else "|",
                        sock.Pid, 
                        la, 
                        sock.Protocol,
                        protos.protos.get(sock.Protocol.v(), "-"),
                        sock.obj_offset,
                        self._config.MACHINE)

                yield self.getoutput(line, sock.CreateTime, body = body)

            stuff = []
            if "EvtLog" in self._config.TYPE:
                evt = evtlogs.EvtLogs(self._config)
                stuff = evt.calculate()
            for name, buf in stuff:
                for fields in evt.parse_evt_info(name, buf, rawtime = True):
                    line = "[{8}EVT LOG]{0} {1}{0} {2}/{3}/{4}/{5}/{6}/{7}".format("" if body else "|",
                            fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7],
                            self._config.MACHINE)
                    yield self.getoutput(line, fields[0], body = body)
        elif version <= (6, 1):
            # Vista+
            nets = []
            if "Socket" in self._config.TYPE:
                nets = netscan.Netscan(self._config).calculate()
            for net_object, proto, laddr, lport, raddr, rport, state in nets:
                conn = "{0}:{1} -> {2}:{3}".format(laddr, lport, raddr, rport)
                line = "[{6}NETWORK CONNECTION]{0} {2}{0} {1}/{3}/{4}/{5:<#10x}".format(
                        "" if body else "|",
                        net_object.Owner.UniqueProcessId,
                        conn,
                        proto,
                        state,
                        net_object.obj_offset,
                        self._config.MACHINE)

                yield self.getoutput(line, net_object.CreateTime, body = body)

        # Get threads
        threads = []
        if "Thread" in self._config.TYPE:
            threads = modscan.ThrdScan(self._config).calculate()
        for thread in threads:
            image = pids.get(thread.Cid.UniqueProcess.v(), "UNKNOWN")
            line = "[{4}THREAD]{0} {1}{0} PID: {2}/TID: {3}".format(
                    "" if body else "|",
                    image,
                    thread.Cid.UniqueProcess,
                    thread.Cid.UniqueThread,
                    self._config.MACHINE)
            yield self.getoutput(line, thread.CreateTime, end = thread.ExitTime, body = body)

    
        data = []
        if "Symlink" in self._config.TYPE:
            data = filescan.SymLinkScan(self._config).calculate()
        for link in data:
            objct = link.get_object_header()
            line = "[{6}SYMLINK]{0} {1}->{2}{0} POffset: {3}/Ptr: {4}/Hnd: {5}".format(
                    "" if body else "|",
                    str(objct.NameInfo.Name or ''),
                    str(link.LinkTarget or ''),
                    link.obj_offset,
                    objct.PointerCount,
                    objct.HandleCount,
                    self._config.MACHINE)
            yield self.getoutput(line, link.CreationTime, body = body)

        data = []
        if "TimeDateStamp" in self._config.TYPE:
            data = moddump.ModDump(self._config).calculate()
        for aspace, procs, mod_base, mod_name in data:
            mod_name = str(mod_name or '')
            space = tasks.find_space(aspace, procs, mod_base)
            if space != None:
                try:
                    pe_file = obj.Object("_IMAGE_DOS_HEADER", offset = mod_base, vm = space)
                    header = pe_file.get_nt_header()
                except ValueError, ve: 
                    continue
                line = "[{3}PE HEADER (module)]{0} {1}{0} Base: {2:#010x}".format(
                        "" if body else "|",
                        mod_name,
                        mod_base,
                        self._config.MACHINE)
                yield self.getoutput(line, header.FileHeader.TimeDateStamp, body = body)

        uastuff = []
        if "Userassist" in self._config.TYPE:
            uastuff = userassist.UserAssist(self._config).calculate()
        for win7, reg, key in uastuff:
            ts = "{0}".format(key.LastWriteTime)
            for v in rawreg.values(key):
                tp, dat = rawreg.value_data(v)
                subname = v.Name
                if tp == 'REG_BINARY':
                    dat_raw = dat
                    try:
                        subname = subname.encode('rot_13')
                    except UnicodeDecodeError:
                        pass
                    if win7:
                        guid = subname.split("\\")[0]
                        if guid in userassist.folder_guids:
                            subname = subname.replace(guid, userassist.folder_guids[guid])
                    bufferas = addrspace.BufferAddressSpace(self._config, data = dat_raw)
                    uadata = obj.Object("_VOLUSER_ASSIST_TYPES", offset = 0, vm = bufferas)
                    ID = "N/A"
                    count = "N/A"
                    fc = "N/A"
                    tf = "N/A"
                    lw = "N/A"
                    if len(dat_raw) < bufferas.profile.get_obj_size('_VOLUSER_ASSIST_TYPES') or uadata == None:
                        continue
                    else:
                        if hasattr(uadata, "ID"):
                            ID = "{0}".format(uadata.ID)
                        if hasattr(uadata, "Count"):
                            count = "{0}".format(uadata.Count)
                        else:
                            count = "{0}".format(uadata.CountStartingAtFive if uadata.CountStartingAtFive < 5 else uadata.CountStartingAtFive - 5)
                        if hasattr(uadata, "FocusCount"):
                            seconds = (uadata.FocusTime + 500) / 1000.0
                            time = datetime.timedelta(seconds = seconds) if seconds > 0 else uadata.FocusTime
                            fc = "{0}".format(uadata.FocusCount)
                            tf = "{0}".format(time)
                        lw = "{0}".format(uadata.LastUpdated)

                subname = subname.replace("|", "%7c")
                line = "[{7}USER ASSIST]{0} {2}{0} Registry: {1}/ID: {3}/Count: {4}/FocusCount: {5}/TimeFocused: {6}".format(
                        "" if body else "|",
                        reg, subname, ID, count, fc, tf,
                        self._config.MACHINE)
                yield self.getoutput(line, uadata.LastUpdated, body = body)

        shimdata = []
        if "Shimcache" in self._config.TYPE:
            shimdata = shimcache.ShimCache(self._config).calculate()
        for path, lm, lu in shimdata:
            line = "[{2}SHIMCACHE]{0} {1}{0} ".format(
                    "" if body else "|",
                    path, self._config.MACHINE)
            if lu:
                yield self.getoutput(line, lm, end = lu, body = body)
            else:
                yield self.getoutput(line, lm, body = body)

        if "_HBASE_BLOCK" in self._config.TYPE or "_CMHIVE" in self._config.TYPE or "Registry" in self._config.TYPE:
            regapi = registryapi.RegistryApi(self._config)
            for o in regapi.all_offsets:
                if "_HBASE_BLOCK" in self._config.TYPE:
                    line = "[{2}_HBASE_BLOCK TimeStamp]{0} {1}{0} ".format(
                        "" if body else "|",
                        regapi.all_offsets[o],
                        self._config.MACHINE)
                    h = obj.Object("_HHIVE", o, addr_space)
                    yield self.getoutput(line, h.BaseBlock.TimeStamp, body = body)


                if "_CMHIVE" in self._config.TYPE and version[0] == 6 and addr_space.profile.metadata.get('build', 0) >= 7601:
                    line = line = "[{2}_CMHIVE LastWriteTime]{0} {1}{0} ".format(
                        "" if body else "|",
                        regapi.all_offsets[o],
                        self._config.MACHINE)
                    cmhive = obj.Object("_CMHIVE", o, addr_space)
                    yield self.getoutput(line, cmhive.LastWriteTime, body = body)

        if "Registry" in self._config.TYPE:
            regapi.reset_current()
            regdata = regapi.reg_get_all_keys(self._config.HIVE, self._config.USER, reg = True, rawtime = True)
    
            for lwtime, reg, item in regdata:
                item = item.replace("|", "%7c")
                line = "[{3}REGISTRY]{0} {2}{0} Registry: {1}".format(
                        "" if body else "|",
                        reg, 
                        item,
                        self._config.MACHINE)
                        
                yield self.getoutput(line, lwtime, body = body)

        if "Timer" in self._config.TYPE:
            volmagic = obj.VolMagic(addr_space)
            KUSER_SHARED_DATA = obj.Object("_KUSER_SHARED_DATA",
                       offset = volmagic.KUSER_SHARED_DATA.v(),
                       vm = addr_space)
            interrupt = (KUSER_SHARED_DATA.InterruptTime.High1Time << 32) | KUSER_SHARED_DATA.InterruptTime.LowPart
            now = KUSER_SHARED_DATA.SystemTime.as_windows_timestamp()
            data = timers.Timers(self._config).calculate()
            for timer, module in data:
                signaled = "-"
                if timer.Header.SignalState.v():
                    signaled = "Yes"

                module_name = "UNKNOWN"
                if module:
                    module_name = str(module.BaseDllName or '')

                try:
                    # human readable time taken from http://computer.forensikblog.de/en/2011/10/timers-and-times.html
                    bufferas = addrspace.BufferAddressSpace(self._config, data = struct.pack('<Q', timer.DueTime.QuadPart - interrupt + now))
                    due_time = obj.Object("WinTimeStamp", is_utc = True, offset = 0, vm = bufferas)
                except TypeError:
                    due_time = 0

                line = "[{6}TIMER]{0} {1}{0} Signaled: {2}/Routine: 0x{3:x}/Period(ms): {4}/Offset: 0x{5:x}".format(
                        "" if body else "|",
                        module_name,
                        signaled,
                        timer.Dpc.DeferredRoutine,
                        timer.Period,
                        timer.obj_offset,
                        self._config.MACHINE)

                yield self.getoutput(line, due_time, body = body)
