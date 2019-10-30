"""
@author:       Sergey Gorbov & Glenn McLellan
@license:      GNU General Public License 2.0
@contact:      sedoy51289@gmail.com & gmclella@my.uno.edu
"""


import struct, math, time
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.linux.common  as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid

node_vtypes_32 = {
    'hashnode': [12 ,{    
    'next': [0, ['pointer', ['node']]],
    'nam': [4, ['pointer' , ['String', dict(length = 1024)]]],
    'flags': [8, ['int']],
    }],
}

zsh_vtypes_32 = {
    'histent': [44, {
    'node':[0, ['hashnode']],
    'up': [12, ['pointer', ['histent']]],
    'down': [16, ['pointer', ['histent']]],
    'zle_text': [20, ['pointer' , ['String', dict(length = 1024)]]],
    'stim': [24, ['int']],
    'ftim': [28, ['int']],
    'words': [32, ['pointer', ['short']]],
    'nwords': [36, ['int']],
    'histnum': [40, ['long']]
    }],
}

node_vtypes_64 = {
    'hashnode': [24 ,{    
    'next': [0, ['pointer', ['node']]],
    'nam': [8, ['pointer' , ['String', dict(length = 1024)]]],
    'flags': [16, ['int']],
    }],
}

zsh_vtypes_64 = {
    'histent': [88, {
    'node':[0, ['hashnode']],
    'up': [24, ['pointer', ['histent']]],
    'down': [32, ['pointer', ['histent']]],
    'zle_text': [40, ['pointer' , ['String', dict(length = 1024)]]],
    'stim': [48, ['int']],
    'ftim': [56, ['int']],
    'words': [64, ['pointer', ['short']]],
    'nwords': [72, ['int']],
    'histnum': [80, ['long']]
    }],
}

plength = None

class hashnode(obj.CType):
    """A class for history entries"""

    def is_valid(self, start_brk, brk):
        
        global plength
        # Check the basic structure members 
        if (not obj.CType.is_valid(self)):
            return False
        if self.nam < start_brk or self.nam > brk-plength:
            return False
        return True

class ZshNodeTypes(obj.ProfileModification):

    def modification(self, profile):
        
        global plength
        
        if profile.metadata.get('memory_model', '32bit') == "32bit":
            profile.vtypes.update(node_vtypes_32)
            plength = 4
        else:
            profile.vtypes.update(node_vtypes_64)
            plength = 8
        
        profile.object_classes.update({"hashnode": hashnode})

class histent(obj.CType):
    """A class for history entries"""

    def is_valid(self, start_brk, brk, tdrift=0, rec=True):
        
        global plength
        # Check the basic structure members 
        if (not obj.CType.is_valid(self)):
            return False
        # At this point the time won't be less then 10 numbers in length
        # As well as a command's time cannot be later than current time
        
        if len(str(self.ftim)) < 10 or self.ftim > time.time()+tdrift or self.ftim < 0:
            return False
        if len(str(self.stim)) < 10 or self.stim > time.time()+tdrift or self.stim < 0:
            return False
        # History HEAD and TAIL will have only one pointer in the heap.
		#    Test if the up and down pointers are both not within heap.
        if (self.up < start_brk or self.up > brk-plength) and (self.down < start_brk or self.down > brk-plength):
            return False
        
        # Checking if the immediate predecessor and descendant are valid 
        up = self.up.dereference_as('histent')
        down = self.down.dereference_as('histent')
        if rec: # Recursion key
            if not up.is_valid(start_brk, brk, tdrift, rec=False) and not down.is_valid(start_brk, brk, tdrift, rec=False):
                return False
        return True
    def get_stim(self):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.stim))
    def get_ftim(self):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.ftim))

class ZshTypes(obj.ProfileModification):
    conditions = {"os" : lambda x : x in ["linux", "mac"]}
    
    def modification(self, profile):
        
        if profile.metadata.get('memory_model', '32bit') == "32bit":
            profile.vtypes.update(zsh_vtypes_32)
        else:
            profile.vtypes.update(zsh_vtypes_64)
        
        profile.object_classes.update({"histent": histent})

class linux_zsh(linux_pslist.linux_pslist):
    """Recover zsh history from zsh process memory"""

    def __init__(self, config, *args, **kwargs): 
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('SCAN_ALL', short_option = 'A', default = False, help = 'scan all processes, not just those named zsh', action = 'store_true')
        self._config.add_option('CARVING', short_option = 'C', default = False, help = 'use carving to recover history entries. Better not to be used with option "A" as it may take indefinetely long', action = 'store_true')
        self._config.add_option('FUTURE_DRIFT', short_option = 'F', default = 0, help = 'use future drift to analyze memory image with time set in future', action = 'store', type = 'int')
        self._config.FUTURE_DRIFT *= 86400 # Seconds in hour
    def calculate(self):
        linux_common.set_plugin_members(self)
    
        tasks = linux_pslist.linux_pslist(self._config).calculate()

        for task in tasks:
            proc_as = task.get_process_address_space()
            
            # In cases when mm is an invalid pointer 
            if not proc_as:
                continue

            # Do we scan everything or just /bin/zsh instances?
            if not (self._config.SCAN_ALL or str(task.comm) == "zsh"):
                continue
            
            for hist in task.zsh_history_entries(self._config.FUTURE_DRIFT, self._config.CARVING):
                    yield task, hist 
            
    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                    ("Name", str),
                    ("HistNum", str),
                    ("CommandTime", str),
                    ("Command", str)],
                        self.generator(data))

    def generator(self, data):
        for task, hist_entry in data:
            yield (0, [int(task.pid), str(task.comm),
                        str(hist_entry[0]), 
                        hist_entry[1].get_stim(),
                        str(hist_entry[1].node.nam.dereference())])
            
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                                  ("Name", "20"),
                                  ("HistNum", "7"),
                                  ("CommandTime", "20"),
                                  ("Command", ""),])
                                    
        for task, hist_entry in data:
            self.table_row(outfd, task.pid, task.comm, 
                           hist_entry[0], 
                           hist_entry[1].get_stim(),
                           hist_entry[1].node.nam.dereference())
