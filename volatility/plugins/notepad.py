# Volatility
#
# Authors:
# Michael Hale Ligh <michael@memoryanalysis.net>
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

import os
import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.taskmods as taskmods
from volatility.renderers import TreeGrid

#--------------------------------------------------------------------------------
# object classes 
#--------------------------------------------------------------------------------   

class _HEAP(obj.CType):
    """ A Heap on XP and 2003 """
        
    def is_valid(self):
        return obj.CType.is_valid(self) and self.Signature == 0xeeffeeff

    def segments(self):
        """ A list of the _HEAP_SEGMENTs. 

        This is an array of pointers so we have to deref
        before returning or the caller will be calling 
        is_valid on the pointer and not the object. 
        """
        return [seg.dereference() for seg in self.Segments if seg != 0]

class _HEAP_SEGMENT(obj.CType):
    """ A Heap Segment on XP and 2003 """    

    def is_valid(self):
        return obj.CType.is_valid(self) and self.Signature == 0xffeeffee

    def heap_entries(self):
        """Enumerate the heaps in this segment. 

        ##FIXME: 
        * Raise ValueError if corruptions are detected. 
        * Should we start at FirstEntry or Entry?
        """

        next = self.Entry #FirstEntry.dereference()
        last = self.LastValidEntry.dereference()

        chunk_size = self.obj_vm.profile.get_obj_size("_HEAP_ENTRY")

        while (next and 
                    next.obj_offset < last.obj_offset):

            yield next

            next = obj.Object("_HEAP_ENTRY", 
                    offset = next.obj_offset + next.Size * chunk_size, 
                    vm = next.obj_vm)

class _HEAP_ENTRY(obj.CType):
    """ A Heap Entry """

    def get_data(self):

        chunk_size = self.obj_vm.profile.get_obj_size("_HEAP_ENTRY")

        return self.obj_vm.zread(
                    self.obj_offset + chunk_size, 
                    self.Size * chunk_size
                    )

    def get_extra(self):

        chunk_size = self.obj_vm.profile.get_obj_size("_HEAP_ENTRY")

        return obj.Object("_HEAP_ENTRY_EXTRA", 
                    offset = self.obj_offset + (chunk_size * (self.Size - 1)), 
                    vm = self.obj_vm)

#--------------------------------------------------------------------------------
# profile modifications
#--------------------------------------------------------------------------------   

class XPHeapModification(obj.ProfileModification):

    before = ["WindowsObjectClasses"]

    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x : x == 5, 
                  'memory_model' : lambda x : x == '32bit'}

    def modification(self, profile):

        heap_flags = {
            'HEAP_NO_SERIALIZE': 0, 
            'HEAP_GROWABLE': 1, 
            'HEAP_GENERATE_EXCEPTIONS': 2, 
            'HEAP_ZERO_MEMORY': 3, 
            'HEAP_REALLOC_IN_PLACE_ONLY': 4, 
            'HEAP_TAIL_CHECKING_ENABLED': 5, 
            'HEAP_FREE_CHECKING_ENABLED': 6, 
            'HEAP_DISABLE_COALESCE_ON_FREE': 7, 
            'HEAP_SETTABLE_USER_VALUE': 8,             
            'HEAP_CREATE_ALIGN_16': 16, 
            'HEAP_CREATE_ENABLE_TRACING': 17, 
            'HEAP_CREATE_ENABLE_EXECUTE': 18, 
            'HEAP_FLAG_PAGE_ALLOCS': 24, 
            'HEAP_PROTECTION_ENABLED': 25, 
            'HEAP_CAPTURE_STACK_BACKTRACES': 27, 
            'HEAP_SKIP_VALIDATION_CHECKS': 28, 
            'HEAP_VALIDATE_ALL_ENABLED': 29, 
            'HEAP_VALIDATE_PARAMETERS_ENABLED': 30, 
            'HEAP_LOCK_USER_ALLOCATED': 31, 
            }

        entry_flags = {
            #'HEAP_ENTRY_BUSY': 0, 
            "busy": 0, 
            #'HEAP_ENTRY_EXTRA_PRESENT': 1,   
            "extra": 1,
            #'HEAP_ENTRY_FILL_PATTERN': 2, 
            "fill": 2, 
            #'HEAP_ENTRY_VIRTUAL_ALLOC': 3, 
            "virtual": 3, 
            #'HEAP_ENTRY_LAST_ENTRY': 4, 
            "last": 4, 
            #'HEAP_ENTRY_SETTABLE_FLAG1': 5, 
            "flag1": 5,
            #'HEAP_ENTRY_SETTABLE_FLAG2': 6, 
            "flag2": 6, 
            #'HEAP_ENTRY_SETTABLE_FLAG3': 7
            "flag3": 7
            }

        profile.merge_overlay({
            '_HEAP': [ None, { 
            'Flags': [ None, ['Flags', {'bitmap': heap_flags}]],
            'ForceFlags': [ None, ['Flags', {'bitmap': heap_flags}]],
            }], 
            '_HEAP_FREE_ENTRY': [ None, { 
            'Flags': [ None, ['Flags', {'target': 'unsigned char', 'bitmap': entry_flags}]],
            }], 
            '_HEAP_ENTRY': [ None, { 
            'Flags': [ None, ['Flags', {'target': 'unsigned char', 'bitmap': entry_flags}]],
            }], 
            '_HEAP_SEGMENT': [ None, { 
            'Flags': [ None, ['Flags', {'bitmap': {'HEAP_USER_ALLOCATED': 0}}]],
            }],
        })

        profile.object_classes.update({
            '_HEAP_ENTRY': _HEAP_ENTRY, 
            '_HEAP': _HEAP, 
            '_HEAP_SEGMENT': _HEAP_SEGMENT, 
        })

class Notepad(taskmods.DllList):
    """List currently displayed notepad text"""

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option("DUMP-DIR", short_option = "D", default = None, 
            help = "Dump binary data to this directory")

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 5)

    def unified_output(self, data):
        return TreeGrid([("Process", str),
                         ("PID", int),
                         ("Text", str),
                         ], self.generator(data))

    def generator(self, data):
        for task in data:
            # only looking for notepad
            if str(task.ImageFileName).lower() != "notepad.exe":
                continue
            process_id = task.UniqueProcessId

            entry_size = task.obj_vm.profile.get_obj_size("_HEAP_ENTRY")
            heap = task.Peb.ProcessHeap.dereference_as("_HEAP")

            for segment in heap.segments():
                for entry in segment.heap_entries():

                    # the extra heap data is present
                    if "extra" not in str(entry.Flags):
                        continue

                    text = obj.Object("String",
                                      offset = entry.obj_offset + entry_size,
                                      vm = task.get_process_address_space(),
                                      length = entry.Size * entry_size,
                                      encoding = "utf16")

                    if not text or len(text) == 0:
                        continue
                    else:
                        display_text = text

            yield(0, ['notepad.exe', int(process_id), str(display_text)])

    def render_text(self, outfd, data):
        for task in data:

            # only looking for notepad
            if str(task.ImageFileName).lower() != "notepad.exe":
                continue
            outfd.write("Process: {0}\n".format(task.UniqueProcessId))

            entry_size = task.obj_vm.profile.get_obj_size("_HEAP_ENTRY")
            heap = task.Peb.ProcessHeap.dereference_as("_HEAP")

            for segment in heap.segments():
                for entry in segment.heap_entries():
                
                    # the extra heap data is present 
                    if "extra" not in str(entry.Flags):
                        continue 

                    text = obj.Object("String", 
                                      offset = entry.obj_offset + entry_size,
                                      vm = task.get_process_address_space(),
                                      length = entry.Size * entry_size,
                                      encoding = "utf16")

                    if not text or len(text) == 0:
                        continue 

                    if self._config.DUMP_DIR:
                        name = "notepad.{0}.txt".format(task.UniqueProcessId)
                        path = os.path.join(self._config.DUMP_DIR, name)
                        with open(path, "wb") as handle:
                            handle.write(entry.get_data())
                        outfd.write("Dumped To: {0}\n".format(path))

                    outfd.write("Text:\n{0}\n\n".format(text))
