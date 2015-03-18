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

import volatility.utils as utils
import volatility.plugins.getsids as getsids
import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.getservicesids as getservicesids
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.debug as debug
import os, datetime, ntpath
from volatility.renderers import TreeGrid

# for more information on Event Log structures see WFA 2E pg 260-263 by Harlan Carvey
evt_log_types = {
    'EVTLogHeader' : [ 0x30, {
        'HeaderSize' : [ 0x0, ['unsigned int']],
        'Magic' : [ 0x4, ['int']],  #LfLe
        'OffsetOldest' : [ 0x10, ['unsigned int']],  #offset of oldest record
        'OffsetNextToWrite' : [ 0x14, ['unsigned int']],  #offset of next record to be written
        'NextID' : [ 0x18, ['int']],  #next event record ID
        'OldestID' : [ 0x1c, ['int']], #oldest event record ID
        'MaxSize' : [ 0x20, ['unsigned int']],  #maximum size of event record (from registry)
        'RetentionTime' : [ 0x28, ['int']], #retention time of records (from registry)
        'RecordSize' : [ 0x2c, ['unsigned int']],  #size of the record (repeat of DWORD at offset 0)
    } ],

    'EVTRecordStruct' : [ 0x38, {
        'RecordLength' : [ 0x0, ['unsigned int']],
        'Magic' : [ 0x4, ['int']],  #LfLe
        'RecordNumber' : [ 0x8, ['int']],
        'TimeGenerated' : [ 0xc, ['UnixTimeStamp', dict(is_utc = True)]], 
        'TimeWritten' : [ 0x10, ['UnixTimeStamp', dict(is_utc = True)]],
        'EventID' : [ 0x14, ['unsigned short']], #specific to event source and uniquely identifies the event
        'EventType' : [ 0x18, ['Enumeration', dict(target = 'unsigned short', choices = {0x01: "Error", 0x02: "Warning", 0x04: "Info", 0x08: "Success", 0x10: "Failure"})]], 
        'NumStrings' : [ 0x1a, ['unsigned short']], #number of description strings in even message
        'EventCategory' : [ 0x1c, ['unsigned short']],
        'ReservedFlags' : [ 0x1e, ['unsigned short']],
        'ClosingRecordNum' : [ 0x20, ['int']],
        'StringOffset' : [ 0x24, ['unsigned int']], #offset w/in record of description strings
        'SidLength' : [ 0x28, ['unsigned int']], #length of SID: if 0 no SID is present
        'SidOffset' : [ 0x2c, ['unsigned int']], #offset w/in record to start of SID (if present)
        'DataLength' : [ 0x30, ['unsigned int']], #length of binary data of record
        'DataOffset' : [ 0x34, ['unsigned int']], #offset of data w/in record
    } ],
}

class EVTObjectTypes(obj.ProfileModification):
    before = ["WindowsVTypes"]
    conditions = {'os': lambda x: x == 'windows', 
                  'major': lambda x: x == 5,  
                  'minor': lambda x: x >= 1}
    def modification(self, profile):
        profile.vtypes.update(evt_log_types)

class EvtLogs(common.AbstractWindowsCommand):
    """Extract Windows Event Logs (XP/2003 only)"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('SAVE-EVT', short_option = 'S', default = False, 
                          action = 'store_true', help = 'Save the raw .evt files also')

        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump executable files')

        self.extrasids = {}

    @staticmethod
    def is_valid_profile(profile):
        """This plugin is valid on XP and 2003"""
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 5)

    def load_user_sids(self):
        """Load the user SIDs from the registry"""
        regapi = registryapi.RegistryApi(self._config)
        regapi.set_current("SOFTWARE")
        for k1 in regapi.reg_enum_key('SOFTWARE', 'Microsoft\\Windows NT\\CurrentVersion\\ProfileList'):
            val = regapi.reg_get_value('SOFTWARE',  k1, 'ProfileImagePath')
            sid = k1.split("\\")[-1]
            if val != None:
                ## Strip NULLs in the value 
                self.extrasids[sid] = " (User: " + val.split("\\")[-1].replace("\x00", "") + ")"

    def get_sid_string(self, data):
        """Take a buffer of data from the event record 
        and parse it as a SID. 
        
        @param data: buffer of data from SidOffset of the 
        event record to SidOffset + SidLength. 
        
        @returns: sid string 
        """
        sid_name = ""
        bufferas = addrspace.BufferAddressSpace(self._config, data = data)
        sid = obj.Object("_SID", offset = 0, vm = bufferas)
        for i in sid.IdentifierAuthority.Value:
            id_auth = i 
        sid_string = "S-" + "-".join(str(i) for i in (sid.Revision, id_auth) + tuple(sid.SubAuthority))
        if sid_string in getsids.well_known_sids:
            sid_name = " ({0})".format(getsids.well_known_sids[sid_string])
        else:
            sid_name_re = getsids.find_sid_re(sid_string, getsids.well_known_sid_re)
            if sid_name_re:
                sid_name = " ({0})".format(sid_name_re)
            else:
                sid_name = self.extrasids.get(sid_string, "")
        sid_string += sid_name
        return sid_string

    def calculate(self):
        addr_space = utils.load_as(self._config)
        
        if not self.is_valid_profile(addr_space.profile):
            debug.error("This plugin only works on XP and 2003")

        ## When verbose is specified, we recalculate the list of SIDs for
        ## services in the registry. Otherwise, we take the list from the 
        ## pre-populated dictionary in getservicesids.py
        if self._config.VERBOSE:
            ssids = getservicesids.GetServiceSids(self._config).calculate()
            for sid, service in ssids:
                self.extrasids[sid] = " (Service: " + service + ")" 
        else:
            for sid, service in getservicesids.servicesids.items():
                self.extrasids[sid] = " (Service: " + service + ")"

        ## Get the user's SIDs from the registry
        self.load_user_sids()

        for proc in tasks.pslist(addr_space):
            if str(proc.ImageFileName).lower() == "services.exe":
                for vad, process_space in proc.get_vads(vad_filter = proc._mapped_file_filter):
                    if vad.FileObject.FileName:
                        name = str(vad.FileObject.FileName).lower()
                        if name.endswith(".evt"):
                            ## Maybe check the length is reasonable, though probably there won't 
                            ## ever be event logs that are multiple GB or TB in size.
                            data = process_space.zread(vad.Start, vad.Length)
                            yield name, data


    def parse_evt_info(self, name, buf, rawtime = False):
        
        loc = buf.find("LfLe")
        
        ## Skip the EVTLogHeader at offset 4. Here you can also parse
        ## and print the header values if you like. 
        if loc == 4:
            loc = buf.find("LfLe", loc + 1)
        
        while loc != -1:
            
            ## This record's data (and potentially the data for records
            ## that follow it, so we'll be careful to chop it in the right
            ## places before future uses). 
            rec = buf[loc - 4:]
            
            ## Use a buffer AS to instantiate the object 
            bufferas = addrspace.BufferAddressSpace(self._config, data = rec)
            evtlog = obj.Object("EVTRecordStruct", offset = 0, vm = bufferas)
            rec_size = bufferas.profile.get_obj_size("EVTRecordStruct")
            
            ## Calculate the SID string. If the SidLength is zero, the next
            ## field (list of strings) starts at StringOffset. If the SidLength
            ## is non-zero, use the data of length SidLength to determine the
            ## SID string and the next field starts at SidOffet.
            if evtlog.SidLength == 0:
                end = evtlog.StringOffset
                sid_string = "N/A"
            else:
                ## detect manged records based on invalid SID length
                if evtlog.SidLength > 68:
                    loc = buf.find("LfLe", loc + 1)
                    continue
                ## these should be appropriately sized SIDs
                end = evtlog.SidOffset
                sid_string = self.get_sid_string(rec[end:end + evtlog.SidLength])

            computer_name = ""
            source = ""

            items = rec[rec_size:end].split("\x00\x00") 
            source = utils.remove_unprintable(items[0])
            if len(items) > 1:
                computer_name = utils.remove_unprintable(items[1])

            strings = rec[evtlog.StringOffset:].split("\x00\x00", evtlog.NumStrings)
            messages = []
            for s in range(min(len(strings), evtlog.NumStrings)):
                messages.append(utils.remove_unprintable(strings[s]))
                
            # We'll just say N/A if there are no messages, otherwise join them
            # together with semi-colons.
            if messages:
                msg = ";".join(messages)
                msg = msg.replace("|", "%7c") 
            else:
                msg = "N/A"

            # Records with an invalid timestamp are ignored entirely
            if evtlog.TimeWritten != None: 
            
                fields = [
                    str(evtlog.TimeWritten) if not rawtime else evtlog.TimeWritten,
                    ntpath.basename(name),
                    computer_name,
                    sid_string,
                    source,
                    str(evtlog.EventID),
                    str(evtlog.EventType), msg]

                yield fields
            
            ## Scan to the next record signature 
            loc = buf.find("LfLe", loc + 1)

    def unified_output(self, data):
        return TreeGrid([("TimeWritten", str),
                       ("LogFile", str),
                       ("ComputerName", str),
                       ("SID", str),
                       ("Source", str),
                       ("EventID", str),
                       ("EventType", str)],
                        self.generator(data))

    def generator(self, data):
        if self._config.DUMP_DIR and not self._config.SAVE_EVT:
            debug.error("Please add --save-evt flag to dump EVT files")
        if self._config.SAVE_EVT and self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if self._config.SAVE_EVT and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for name, buf in data:
            ## Dump the raw event log so it can be parsed with other tools
            if self._config.SAVE_EVT:
                ofname = ntpath.basename(name)
                fh = open(os.path.join(self._config.DUMP_DIR, ofname), 'wb')
                fh.write(buf)
                fh.close()
                print 'Saved raw .evt file to {0}'.format(ofname)
            for fields in self.parse_evt_info(name, buf):
                yield (0, [str(fields[0]), str(fields[1]), str(fields[2]), str(fields[3]), str(fields[4]), str(fields[5]), str(fields[6])])

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for name, buf in data: 
            ## We can use the ntpath module instead of manually replacing the slashes
            ofname = ntpath.basename(name)
            
            ## Dump the raw event log so it can be parsed with other tools
            if self._config.SAVE_EVT:
                fh = open(os.path.join(self._config.DUMP_DIR, ofname), 'wb')
                fh.write(buf)
                fh.close()
                outfd.write('Saved raw .evt file to {0}\n'.format(ofname))
            
            ## Now dump the parsed, pipe-delimited event records to a file
            ofname = ofname.replace(".evt", ".txt")
            fh = open(os.path.join(self._config.DUMP_DIR, ofname), 'wb')
            for fields in self.parse_evt_info(name, buf):
                fh.write('|'.join(fields) + "\n")    
            fh.close()
            outfd.write('Parsed data sent to {0}\n'.format(ofname))
