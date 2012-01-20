# Volatility
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

import copy
import volatility.plugins.overlays.basic as basic
import volatility.plugins.overlays.windows.windows as windows

# This is the location of the MMVAD type which controls how to parse the
# node. It is located before the structure.
windows_overlay['VOLATILITY_MAGIC'][0]['_MMVAD_SHORT'][1]['Tag'][0] = -12
windows_overlay['VOLATILITY_MAGIC'][0]['_MMVAD_LONG'][1]['Tag'][0] = -12

class AbstractWindowsX64(windows.AbstractWindowsX86):
    """ A Profile for Windows systems """
    _md_os = 'windows'
    _md_memory_model = '64bit'
    native_types = basic.x64_native_types
    object_classes = copy.deepcopy(windows.AbstractWindows.object_classes)

    def list_to_type(self, name, typeList, typeDict = None):
        """Handle pointer64 types as if they were pointer types on 64-bit systems"""
        if typeList[0] == 'pointer64':
            typeList[0] = 'pointer'
        return super(AbstractWindowsX64, self).list_to_type(name, typeList, typeDict)
