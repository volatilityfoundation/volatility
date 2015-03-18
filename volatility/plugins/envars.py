# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2012 Michael Ligh <michael.ligh@mnin.org>
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

import volatility.plugins.taskmods as taskmods
import volatility.plugins.registry.registryapi as registryapi
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class Envars(taskmods.DllList):
    "Display process environment variables"

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option("SILENT", short_option = 's', 
                          default = False,
                          help = "Suppress common and non-persistent variables", 
                          action = "store_true")

    def _get_silent_vars(self):
        """Enumerate persistent & common variables.
        
        This function collects the global (all users) and 
        user-specific environment variables from the 
        registry. Any variables in a process env block that
        does not exist in the persistent list was explicitly
        set with the SetEnvironmentVariable() API.
        """
    
        values = []

        regapi = registryapi.RegistryApi(self._config)
        ccs = regapi.reg_get_currentcontrolset()
        
        ## The global variables 
        for value, _ in regapi.reg_yield_values(
                            hive_name = 'system', 
                            key = '{0}\\Control\\Session Manager\\Environment'.format(ccs)):
            values.append(value)

        ## The user-specific variables 
        regapi.reset_current()
        for value, _ in regapi.reg_yield_values(
                            hive_name = 'ntuser.dat', key = 'Environment'):
            values.append(value)

        ## The volatile user variables 
        for value, _ in regapi.reg_yield_values(
                            hive_name = 'ntuser.dat', key = 'Volatile Environment'):
            values.append(value)

        ## These are variables set explicitly but are
        ## common enough to ignore safely. 
        values.extend(["ProgramFiles", "CommonProgramFiles", "SystemDrive", 
                "SystemRoot", "ProgramData", "PUBLIC", "ALLUSERSPROFILE", 
                "COMPUTERNAME", "SESSIONNAME", "USERNAME", "USERPROFILE", 
                "PROMPT", "USERDOMAIN", "AppData", "CommonFiles", "CommonDesktop", 
                "CommonProgramGroups", "CommonStartMenu", "CommonStartUp", 
                "Cookies", "DesktopDirectory", "Favorites", "History", "NetHood", 
                "PersonalDocuments", "RecycleBin", "StartMenu", "Templates", 
                "AltStartup", "CommonFavorites", "ConnectionWizard", 
                "DocAndSettingRoot", "InternetCache", "windir", "Path", "HOMEDRIVE", 
                "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "ProgramFiles(x86)", 
                "CommonProgramFiles(x86)", "CommonProgramW6432", "PSModulePath", 
                "PROCESSOR_IDENTIFIER", "FP_NO_HOST_CHECK", "LOCALAPPDATA", "TMP", 
                "ProgramW6432", 
                ])

        return values

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                       ("Process", str),
                       ("Block", Address),
                       ("Variable", str),
                       ("Value", str)],
                        self.generator(data))

    def generator(self, data):
        if self._config.SILENT:
            silent_vars = self._get_silent_vars()

        for task in data:
            for var, val in task.environment_variables():
                if self._config.SILENT:
                    if var in silent_vars:
                        continue 
                yield (0, [int(task.UniqueProcessId),
                        str(task.ImageFileName),
                        Address(task.Peb.ProcessParameters.Environment),
                        str(var),
                        str(val)])

    def render_text(self, outfd, data):

        self.table_header(outfd,
            [("Pid", "8"),
             ("Process", "20"),
             ("Block", "[addrpad]"),
             ("Variable", "30"),
             ("Value", ""),
            ])

        if self._config.SILENT:
            silent_vars = self._get_silent_vars()

        for task in data:
            for var, val in task.environment_variables():
                if self._config.SILENT:
                    if var in silent_vars:
                        continue 
                self.table_row(outfd,
                    task.UniqueProcessId,
                    task.ImageFileName,
                    task.Peb.ProcessParameters.Environment, 
                    var, val
                    )
