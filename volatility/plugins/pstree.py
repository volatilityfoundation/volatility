# Volatility
#
# Authors
# Michael Cohen <scudette@users.sourceforge.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""pstree example file"""

import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.obj as obj

#pylint: disable-msg=C0111

class ProcessAuditVTypes(obj.ProfileModification):
    before = ["WindowsVTypes"]
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        profile.vtypes.update({
            '_SE_AUDIT_PROCESS_CREATION_INFO' : [ 0x4, {
            'ImageFileName' : [ 0x0, ['pointer', ['_OBJECT_NAME_INFORMATION']]],
            }],
            '_OBJECT_NAME_INFORMATION' : [ 0x8, {
            'Name' : [ 0x0, ['_UNICODE_STRING']],
            }]})

class PSTree(common.AbstractWindowsCommand):
    """Print process list as a tree"""

    def find_root(self, pid_dict, pid):
        # Prevent circular loops.
        seen = set()

        while pid in pid_dict and pid not in seen:
            seen.add(pid)
            pid = int(pid_dict[pid]['inherited_from'])

        return pid

    def render_text(self, outfd, data):

        self.table_header(outfd, 
                         [("Name", "<50"), 
                          ("Pid", ">6"),
                          ("PPid", ">6"),
                          ("Thds", ">6"),
                          ("Hnds", ">6"),
                          ("Time", "20")])

        def draw_branch(pad, inherited_from):
            for task, task_info in data.items():
                if task_info['inherited_from'] == inherited_from:

                    self.table_row(outfd, 
                        "{0} {1:#x}:{2:20}".format("." * pad, task_info['eprocess'].obj_offset, task_info['image_file_name']),
                        task_info['process_id'],
                        task_info['inherited_from'],
                        task_info['active_threads'],
                        task_info['handle_count'],
                        task_info['create_time'])

                    if self._config.VERBOSE:
                        try:
                            outfd.write("{0}    cmd: {1}\n".format(
                                ' ' * pad, task_info['command_line']))
                            outfd.write("{0}    path: {1}\n".format(
                                ' ' * pad, task_info['ImagePathName']))
                            outfd.write("{0}    audit: {1}\n".format(
                                ' ' * pad, task_info['Audit ImageFileName']))
                        except KeyError:
                            pass

                    del data[task]
                    draw_branch(pad + 1, task_info['process_id']) 

        while len(data.keys()) > 0:
            keys = data.keys()
            root = self.find_root(data, keys[0])
            draw_branch(0, root)

    @cache.CacheDecorator(lambda self: "tests/pstree/verbose={0}".format(self._config.VERBOSE))
    def calculate(self):
        result = {}

        ## Load a new address space
        addr_space = utils.load_as(self._config)

        for task in tasks.pslist(addr_space):
            task_info = {}
            task_info['eprocess'] = task
            task_info['image_file_name'] = task.ImageFileName or 'UNKNOWN'
            task_info['process_id'] = task.UniqueProcessId
            task_info['active_threads'] = task.ActiveThreads
            task_info['inherited_from'] = task.InheritedFromUniqueProcessId
            task_info['handle_count'] = task.ObjectTable.HandleCount
            task_info['create_time'] = task.CreateTime

            ## Get the Process Environment Block - Note that _EPROCESS
            ## will automatically switch to process address space by
            ## itself.
            if self._config.VERBOSE:
                peb = task.Peb
                if peb:
                    task_info['command_line'] = peb.ProcessParameters.CommandLine
                    task_info['ImagePathName'] = peb.ProcessParameters.ImagePathName

                task_info['Audit ImageFileName'] = task.SeAuditProcessCreationInfo.ImageFileName.Name or 'UNKNOWN'

            result[int(task_info['process_id'])] = task_info

        return result
