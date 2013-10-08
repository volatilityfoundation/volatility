# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2012 Michael Ligh <michael.ligh@mnin.org>
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

class Envars(taskmods.DllList):
    "Display process environment variables"

    def render_text(self, outfd, data):

        self.table_header(outfd,
            [("Pid", "8"),
             ("Process", "20"),
             ("Block", "[addrpad]"),
             ("Variable", "30"),
             ("Value", ""),
            ])

        for task in data:
            for var, val in task.environment_variables():
                self.table_row(outfd,
                    task.UniqueProcessId,
                    task.ImageFileName,
                    task.Peb.ProcessParameters.Environment, 
                    var, val
                    )
