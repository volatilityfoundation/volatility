# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
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
## http://www.docslide.com/forensic-analysis-of-internet-explorer-activity-files/
## http://libmsiecf.googlecode.com/files/MSIE%20Cache%20File%20%28index.dat%29%20format.pdf

import volatility.obj as obj
import volatility.plugins.taskmods as taskmods
import volatility.utils as utils
import volatility.win32.tasks as tasks

class _URL_RECORD(obj.CType):
    """A class for URL and LEAK records"""

    def is_valid(self):
        return obj.CType.is_valid(self) and self.Length > 0 and self.Length < 32768

    @property
    def Length(self):
        return self.m('Length') * 0x80
        
    def has_data(self):
        """Determine if a record has data"""
        ## for LEAK records the DataOffset is sometimes 0xdeadbeef
        return (self.DataOffset > 0 and self.DataOffset < self.Length 
                and not self.Url.split(":")[0] 
                in ["PrivacIE", "ietld", "iecompat", "Visited"])

class IEHistoryVTypes(obj.ProfileModification):
    """Apply structures for IE history parsing"""
    
    conditions = {'os': lambda x: x == 'windows'}
    
    def modification(self, profile):        
        profile.vtypes.update({
            '_URL_RECORD' : [ None, {
            'Signature' : [ 0, ['String', dict(length = 4)]], 
            'Length' : [ 0x4, ['unsigned int']], 
            'LastModified' : [ 0x08, ['WinTimeStamp', dict(is_utc = True)]], # secondary
            'LastAccessed' : [ 0x10, ['WinTimeStamp', dict(is_utc = True)]], # primary
            'UrlOffset' : [ 0x34, ['unsigned char']], 
            'FileOffset' : [ 0x3C, ['unsigned int']], 
            'DataOffset' : [ 0x44, ['unsigned int']], 
            'DataSize': [ 0x48, ['unsigned int']], 
            'Url' : [ lambda x : x.obj_offset + x.UrlOffset, ['String', dict(length = 4096)]], 
            'File' : [ lambda x : x.obj_offset + x.FileOffset, ['String', dict(length = 4096)]], 
            'Data' : [ lambda x : x.obj_offset + x.DataOffset, ['String', dict(length = 4096)]], 
            }], 
            '_REDR_RECORD' : [ None, {
            'Signature' : [ 0, ['String', dict(length = 4)]], 
            'Length' : [ 0x4, ['unsigned int']], 
            'Url' : [ 0x10, ['String', dict(length = 4096)]], 
            }],
        })
            
        profile.object_classes.update({
            '_URL_RECORD' : _URL_RECORD, 
            '_REDR_RECORD': _URL_RECORD,
        })

class IEHistory(taskmods.DllList):
    """Reconstruct Internet Explorer cache / history"""

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option("LEAK", short_option = 'L', 
                        default = False, action = 'store_true',
                        help = 'Find LEAK records (deleted)')
        config.add_option("REDR", short_option = 'R', 
                        default = False, action = 'store_true',
                        help = 'Find REDR records (redirected)')

    def calculate(self):
        kernel_space = utils.load_as(self._config)
        
        ## Select the tags to scan for. Always find visited URLs,
        ## but make freed and redirected records optional. 
        tags = ["URL "]
        if self._config.LEAK:
            tags.append("LEAK")
        if self._config.REDR:
            tags.append("REDR")
            
        ## Define the record type based on the tag
        tag_records = {
            "URL " : "_URL_RECORD", 
            "LEAK" : "_URL_RECORD", 
            "REDR" : "_REDR_RECORD"}
 
        ## Enumerate processes based on the --pid and --offset 
        for proc in self.filter_tasks(tasks.pslist(kernel_space)):
        
            ## Acquire a process specific AS
            ps_as = proc.get_process_address_space()
            
            for hit in proc.search_process_memory(tags):
                ## Get a preview of the data to see what tag was detected 
                tag = ps_as.read(hit, 4)
                
                ## Create the appropriate object type based on the tag 
                record = obj.Object(tag_records[tag], offset = hit, vm = ps_as)
                if record.is_valid():
                    yield proc, record
    
    def render_text(self, outfd, data):
        for process, record in data:
            outfd.write("*" * 50 + "\n")
            outfd.write("Process: {0} {1}\n".format(process.UniqueProcessId, process.ImageFileName))
            outfd.write("Cache type \"{0}\" at {1:#x}\n".format(record.Signature, record.obj_offset))
            outfd.write("Record length: {0:#x}\n".format(record.Length))
            outfd.write("Location: {0}\n".format(record.Url))
            ## Extended fields are available for these records 
            if record.obj_name == "_URL_RECORD":
                outfd.write("Last modified: {0}\n".format(record.LastModified))
                outfd.write("Last accessed: {0}\n".format(record.LastAccessed))
                outfd.write("File Offset: {0:#x}, Data Offset: {1:#x}, Data Length: {2:#x}\n".format(record.Length, record.FileOffset, record.DataOffset, record.DataSize))
                if record.FileOffset > 0:
                    outfd.write("File: {0}\n".format(record.File))
                if record.has_data():
                    outfd.write("Data: {0}\n".format(record.Data))
                    
    def render_csv(self, outfd, data):
        for process, record in data:
            if record.obj_name == "_URL_RECORD":
                t1 = str(record.LastModified or '')
                t2 = str(record.LastAccessed or '')
            else:
                t1 = t2 = ""
            outfd.write("{0},{1},{2},{3}\n".format(record.Signature, t1.strip(), t2.strip(), record.Url))
    
