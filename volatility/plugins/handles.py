# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# Additional Authors:
# Michael Ligh <michael.ligh@mnin.org>
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

import volatility.plugins.taskmods as taskmods

# Inherit from Dlllist for command line options
class Handles(taskmods.DllList):
    """Print list of open handles for each process"""

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option("PHYSICAL-OFFSET", short_option = 'P', default = False,
                          help = "Physical Offset", action = "store_true")
        config.add_option("OBJECT-TYPE", short_option = 't', default = None,
                          help = 'Show these object types (comma-separated)',
                          action = 'store', type = 'str')
        config.add_option("SILENT", short_option = 's', default = False,
                          action = 'store_true', help = 'Suppress less meaningful results')

    def render_text(self, outfd, data):
        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"

        self.table_header(outfd,
                          [("Offset{0}".format(offsettype), "[addrpad]"),
                           ("Pid", ">6"),
                           ("Handle", "[addr]"),
                           ("Access", "[addr]"),
                           ("Type", "16"),
                           ("Details", "")
                           ])

        if self._config.OBJECT_TYPE:
            object_list = [s for s in self._config.OBJECT_TYPE.split(',')]
        else:
            object_list = []

        for pid, handle, object_type, name in data:
            if object_list and object_type not in object_list:
                continue
            if self._config.SILENT:
                if len(name.replace("'", "")) == 0:
                    continue
            if not self._config.PHYSICAL_OFFSET:
                offset = handle.Body.obj_offset
            else:
                offset = handle.obj_vm.vtop(handle.Body.obj_offset)

            self.table_row(outfd, offset, pid, handle.HandleValue, handle.GrantedAccess, object_type, name)

    def calculate(self):

        for task in taskmods.DllList.calculate(self):
            pid = task.UniqueProcessId
            if task.ObjectTable.HandleTableList:
                for handle in task.ObjectTable.handles():
                    name = ""
                    object_type = handle.get_object_type()
                    if object_type == "File":
                        file_obj = handle.dereference_as("_FILE_OBJECT")
                        name = str(file_obj.file_name_with_device())
                    elif object_type == "Key":
                        key_obj = handle.dereference_as("_CM_KEY_BODY")
                        name = key_obj.full_key_name()
                    elif object_type == "Process":
                        proc_obj = handle.dereference_as("_EPROCESS")
                        name = "{0}({1})".format(proc_obj.ImageFileName, proc_obj.UniqueProcessId)
                    elif object_type == "Thread":
                        thrd_obj = handle.dereference_as("_ETHREAD")
                        name = "TID {0} PID {1}".format(thrd_obj.Cid.UniqueThread, thrd_obj.Cid.UniqueProcess)
                    elif handle.NameInfo.Name == None:
                        name = ''
                    else:
                        name = str(handle.NameInfo.Name)

                    yield pid, handle, object_type, name
