# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2012, 2013 Cem Gurkok <cemgurkok@gmail.com>
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
@author:       Cem Gurkok
@license:      GNU General Public License 2.0
@contact:      cemgurkok@gmail.com
@organization: Volatility Foundation
"""

import re
import volatility.renderers as renderers
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.taskmods as taskmods

class TokenXP2003(obj.ProfileModification):
    before = ['WindowsOverlay', 'WindowsVTypes']
    conditions = {'os': lambda x: x == 'windows', 'major': lambda x: x < 6}
    def modification(self, profile):
        profile.merge_overlay({"_TOKEN" : [None,
                {'Privileges': [None,
                ['pointer', ['array', lambda x: x.PrivilegeCount, ['_LUID_AND_ATTRIBUTES']]]],
                }]})

PRIVILEGE_INFO = {
    2: ('SeCreateTokenPrivilege', "Create a token object"),
    3: ('SeAssignPrimaryTokenPrivilege', "Replace a process-level token"),
    4: ('SeLockMemoryPrivilege', "Lock pages in memory"),
    5: ('SeIncreaseQuotaPrivilege', "Increase quotas"),
    6: ('SeMachineAccountPrivilege', "Add workstations to the domain"),
    7: ('SeTcbPrivilege', "Act as part of the operating system"),
    8: ('SeSecurityPrivilege', "Manage auditing and security log"),
    9: ('SeTakeOwnershipPrivilege', "Take ownership of files/objects"),
    10: ('SeLoadDriverPrivilege', "Load and unload device drivers"),
    11: ('SeSystemProfilePrivilege', "Profile system performance"),
    12: ('SeSystemtimePrivilege', "Change the system time"),
    13: ('SeProfileSingleProcessPrivilege', "Profile a single process"),
    14: ('SeIncreaseBasePriorityPrivilege', "Increase scheduling priority"),
    15: ('SeCreatePagefilePrivilege', "Create a pagefile"),
    16: ('SeCreatePermanentPrivilege', "Create permanent shared objects"),
    17: ('SeBackupPrivilege', "Backup files and directories"),
    18: ('SeRestorePrivilege', "Restore files and directories"),
    19: ('SeShutdownPrivilege', "Shut down the system"),
    20: ('SeDebugPrivilege', "Debug programs"),
    21: ('SeAuditPrivilege', "Generate security audits"),
    22: ('SeSystemEnvironmentPrivilege', "Edit firmware environment values"),
    23: ('SeChangeNotifyPrivilege', "Receive notifications of changes to files or directories"),
    24: ('SeRemoteShutdownPrivilege', "Force shutdown from a remote system"),
    25: ('SeUndockPrivilege', "Remove computer from docking station"),
    26: ('SeSyncAgentPrivilege', "Synch directory service data"),
    27: ('SeEnableDelegationPrivilege', "Enable user accounts to be trusted for delegation"),
    28: ('SeManageVolumePrivilege', "Manage the files on a volume"),
    29: ('SeImpersonatePrivilege', "Impersonate a client after authentication"),
    30: ('SeCreateGlobalPrivilege', "Create global objects"),
    31: ('SeTrustedCredManAccessPrivilege', "Access Credential Manager as a trusted caller"),
    32: ('SeRelabelPrivilege', "Modify the mandatory integrity level of an object"),
    33: ('SeIncreaseWorkingSetPrivilege', "Allocate more memory for user applications"),
    34: ('SeTimeZonePrivilege', "Adjust the time zone of the computer's internal clock"),
    35: ('SeCreateSymbolicLinkPrivilege', "Required to create a symbolic link"),
}

class Privs(taskmods.DllList):
    "Display process privileges"

    def __init__(self, config, *args):
        taskmods.DllList.__init__(self, config, *args)
        config.add_option("SILENT", short_option = "s", default = False,
                          help = "Suppress less meaningful results",
                          action = "store_true")
        config.add_option('REGEX', short_option = 'r',
                          help = 'Show privileges matching REGEX',
                          action = 'store', type = 'string')

    def generator(self, data):
        if self._config.REGEX:
            priv_re = re.compile(self._config.REGEX, re.I)
        for task in data:

            for value, present, enabled, default in task.get_token().privileges():
                # Skip privileges whose bit positions cannot be
                # translated to a privilege name
                try:
                    name, desc = PRIVILEGE_INFO[int(value)]
                except KeyError:
                    continue
                # If we're operating in silent mode, only print privileges
                # that have been explicitly enabled by the process or that
                # appear to have been DKOM'd via Ceasar's proposed attack.
                if self._config.SILENT:
                    if not ((enabled and not default) or (enabled and not present)):
                        continue

                # Set the attributes
                attributes = []
                if present:
                    attributes.append("Present")
                if enabled:
                    attributes.append("Enabled")
                if default:
                    attributes.append("Default")

                if self._config.REGEX:
                    if not priv_re.search(name):
                        continue

                yield (0,
                       [int(task.UniqueProcessId),
                        str(task.ImageFileName),
                        int(value),
                        str(name),
                        ",".join(attributes),
                        str(desc)])

    def unified_output(self, data):

        return renderers.TreeGrid([("Pid", int),
                                 ("Process", str),
                                 ("Value", int),
                                 ("Privilege", str),
                                 ("Attributes", str),
                                 ("Description", str)],
                                  self.generator(data))

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"), 
                                  ("Process", "16"), 
                                  ("Value", "6"),
                                  ("Privilege", "36"), 
                                  ("Attributes", "24"), 
                                  ("Description", "")])

        if self._config.REGEX:
            priv_re = re.compile(self._config.REGEX, re.I)

        for task in data:
            for value, present, enabled, default in task.get_token().privileges():
                # Skip privileges whose bit positions cannot be 
                # translated to a privilege name 
                try:
                    name, desc = PRIVILEGE_INFO[int(value)]
                except KeyError:
                    continue 
                # If we're operating in silent mode, only print privileges
                # that have been explicitly enabled by the process or that 
                # appear to have been DKOM'd via Ceasar's proposed attack. 
                if self._config.SILENT:
                    if not ((enabled and not default) or (enabled and not present)):
                        continue 

                # Set the attributes 
                attributes = []
                if present:
                    attributes.append("Present")
                if enabled:
                    attributes.append("Enabled")
                if default:
                    attributes.append("Default")

                if self._config.REGEX:
                    if not priv_re.search(name):
                        continue 

                self.table_row(outfd, task.UniqueProcessId, task.ImageFileName,
                               value, name, ",".join(attributes), desc)
