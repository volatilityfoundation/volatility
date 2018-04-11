# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
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
## http://www.docslide.com/forensic-analysis-of-internet-explorer-activity-files/
## http://libmsiecf.googlecode.com/files/MSIE%20Cache%20File%20%28index.dat%29%20format.pdf

import volatility.obj as obj
import volatility.plugins.taskmods as taskmods
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.debug as debug
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class _URL_RECORD(obj.CType):
    """A class for URL and LEAK records"""

    def is_valid(self):
        ret = False
        
        if obj.CType.is_valid(self) and self.Length > 0 and self.Length < 32768:
            if not str(self.LastModified).startswith("1970-01-01") and str(self.LastModified) != "-": 
                if not str(self.LastAccessed).startswith("1970-01-01") and str(self.LastAccessed) != "-": 
                    ret = True

        return ret
         
    @property
    def Length(self):
        return self.m('Length') * 0x80
        
    def has_data(self):
        """Determine if a record has data"""
        ## for LEAK records the DataOffset is sometimes 0xdeadbeef
        return (self.DataOffset > 0 and self.DataOffset < self.Length 
                and not self.Url.split(":")[0] 
                in ["PrivacIE", "ietld", "iecompat", "Visited"])

class _DEST_RECORD(obj.CType):
   
    def is_valid(self):
        ret = False

        if obj.CType.is_valid(self) and self.LastModified.is_valid() and self.LastAccessed.is_valid():
             if not str(self.LastModified).startswith("1970-01-01") and str(self.LastModified) != "-": 
                if not str(self.LastAccessed).startswith("1970-01-01") and str(self.LastAccessed) != "-":  
                    if 1999 < self.LastModified.as_datetime().year < 2075 and 1999 < self.LastAccessed.as_datetime().year < 2075 and self.URLStart.is_valid():
                        ret = True
        return ret
 
    def url_and_title(self):
        url_buf = self.obj_vm.zread(self.URLStart.obj_offset, 4096)

        url   = ""
        title = ""

        # look for where url ends
        idx = url_buf.find("\x00\x00")
        if idx > 0:
            idx = idx + 2
            tmpurl = url_buf[:idx]
            for u in tmpurl:
                if 31 < ord(u) < 127:
                    url = url + u

            idx2 = url_buf[idx:].find("\x00\x00")
            if idx2 > 0:
                tmptitle = url_buf[idx:idx+idx2+2]
                for t in tmptitle:
                    if 31 < ord(t) < 127:
                        title = title + t

        return url, title
        
    @property
    def Url(self):
        return self.url_and_title()[0]

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
            '_DEST_RECORD' : [None, {
            'Signature' : [ 0, ['String', dict(length = 4)]], 
            'LastModified' : [ 28, ['WinTimeStamp', dict(is_utc = True)]], 
            'LastAccessed' : [ 36, ['WinTimeStamp', dict(is_utc = True)]], 
            'URLStart'     : [ 94, ['unsigned char']], 
            }],

        })
            
        profile.object_classes.update({
            '_URL_RECORD' : _URL_RECORD, 
            '_REDR_RECORD': _URL_RECORD,
            '_DEST_RECORD' : _DEST_RECORD,
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

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'unknown') == 'windows' 

    def calculate(self):
        ## Select the tags to scan for. Always find visited URLs,
        ## but make freed and redirected records optional. 
        tags = ["URL ", "DEST"]
        if self._config.LEAK:
            tags.append("LEAK")
        if self._config.REDR:
            tags.append("REDR")

        ## Define the record type based on the tag
        tag_records = {
            "URL " : "_URL_RECORD", 
            "LEAK" : "_URL_RECORD", 
            "REDR" : "_REDR_RECORD",
            "DEST" : "_DEST_RECORD"}
 
        vad_filter = lambda x : (hasattr(x, 'ControlArea') and str(x.FileObject.FileName or '').endswith("index.dat")) or (x.VadFlags.Protection.v() == 4)  

        ## Enumerate processes based on the --pid and --offset 
        for proc in taskmods.DllList(self._config).calculate():
        
            ## Acquire a process specific AS
            ps_as = proc.get_process_address_space()
            
            for hit in proc.search_process_memory(tags, vad_filter = vad_filter):
                ## Get a preview of the data to see what tag was detected 
                tag = ps_as.read(hit, 4)

                ## Create the appropriate object type based on the tag 
                record = obj.Object(tag_records[tag], offset = hit, vm = ps_as)
                if record.is_valid():
                    yield proc, record
    
    def unified_output(self, data):
        return TreeGrid([("Process", str),
                       ("PID", int),
                       ("CacheType", str),
                       ("Offset", Address),
                       ("RecordLength", int),
                       ("Location", str),
                       ("LastModified", str),
                       ("LastAccessed", str),
                       ("Length", int),
                       ("FileOffset", Address),
                       ("DataOffset", Address),
                       ("DataSize", int),
                       ("File", str),
                       ("Data", str)],
                        self.generator(data))

    def generator(self, data):
        for process, record in data:
            lm = -1
            la = -1
            length = -1
            fileoffset = -1
            dataoffset = -1
            datasize = -1
            thefile = ""
            thedata = ""
            
            if record.obj_name == "_URL_RECORD":
                lm = str(record.LastModified)
                la = str(record.LastAccessed)
                length = int(record.Length)
                fileoffset = int(record.FileOffset)
                dataoffset = int(record.DataOffset)
                datasize = int(record.DataSize)
                if record.FileOffset > 0:
                    thefile = str(record.File or "")
                if record.has_data():
                    thedata = str(record.Data or "")
            yield (0, [str(process.ImageFileName), 
                        int(process.UniqueProcessId),
                        str(record.Signature),
                        Address(record.obj_offset),
                        int(record.Length),
                        str(record.Url),
                        str(lm),
                        str(la),
                        int(length),
                        Address(fileoffset),
                        Address(dataoffset),
                        int(datasize),
                        str(thefile),
                        str(thedata)])


    def render_text(self, outfd, data):
        for process, record in data:
            if record.obj_name == "_DEST_RECORD":
                url, title = record.url_and_title()

                if len(url) > 4:
                    outfd.write("*" * 50 + "\n")
                    outfd.write("Process: {0} {1}\n".format(process.UniqueProcessId, process.ImageFileName))
                    outfd.write("Cache type \"{0}\" at {1:#x}\n".format(record.Signature, record.obj_offset))
                    outfd.write("Last modified: {0}\n".format(record.LastModified))
                    outfd.write("Last accessed: {0}\n".format(record.LastAccessed))
                    outfd.write("URL: {0}\n".format(url)) 
                    if len(title) > 4:
                        outfd.write("Title: {0}\n".format(title)) 
            else:
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
    
