# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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

"""
@author:       AAron Walters and Nick Petroni
@license:      GNU General Public License 2.0 or later
@contact:      awalters@komoku.com, npetroni@komoku.com
@organization: Komoku, Inc.
"""

#pylint: disable-msg=C0111
import volatility.win32.tasks as tasks

def lsmod(addr_space):
    """ A Generator for modules (uses _KPCR symbols) """
    ## Locate the kpcr struct - either hard coded or specified by the command line

    PsLoadedModuleList = tasks.get_kdbg(addr_space).PsLoadedModuleList

    if PsLoadedModuleList.is_valid():
        ## Try to iterate over the process list in PsActiveProcessHead
        ## (its really a pointer to a _LIST_ENTRY)
        for l in PsLoadedModuleList.dereference_as("_LIST_ENTRY").list_of_type(
            "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"):
            yield l
