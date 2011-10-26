# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
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
@author:       AAron Walters 
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.utils as utils

class TasksNotFound(utils.VolatilityException):
    """Thrown when a tasklist cannot be determined"""
    pass

def get_kdbg(addr_space):
    """A function designed to return the KDDEBUGGER structure from an address space"""

    def verify_kdbg(kdbgobj):
        """Returns true if the kdbg_object handed in appears valid"""
        # Check the OwnerTag is in fact the string KDBG
        return kdbgobj.Header.OwnerTag == 0x4742444B

    kdbgo = obj.VolMagic(addr_space).KDBG.v()

    kdbg = obj.Object("_KDDEBUGGER_DATA64", offset = kdbgo, vm = addr_space)

    if verify_kdbg(kdbg):
        return kdbg
    else:
        # Fall back to finding it via the KPCR
        kpcra = obj.VolMagic(addr_space).KDBG.v()
        kpcrval = obj.Object("_KPCR", offset = kpcra, vm = addr_space)

        DebuggerDataList = kpcrval.KdVersionBlock.dereference_as("_DBGKD_GET_VERSION64").DebuggerDataList

        kobj = DebuggerDataList.dereference_as("_KDDEBUGGER_DATA64")
        if verify_kdbg(kobj):
            return kobj

    return obj.NoneObject("KDDEBUGGER structure not found using either KDBG signature or KPCR pointer")

def pslist(addr_space):
    """ A Generator for _EPROCESS objects (uses _KPCR symbols) """

    PsActiveProcessHead = get_kdbg(addr_space).PsActiveProcessHead

    PsActiveList = PsActiveProcessHead.dereference_as("_LIST_ENTRY")
    if PsActiveList:
        # Try to iterate over the process list in PsActiveProcessHead
        # (its really a pointer to a _LIST_ENTRY)
        for l in PsActiveList.list_of_type("_EPROCESS", "ActiveProcessLinks"):
            yield l
    else:
        raise TasksNotFound("Could not list tasks, please verify the --profile option and whether this image is valid")

def find_space(addr_space, procs, mod_base):
    """Search for an address space (usually looking for a GUI process)"""
    if addr_space.is_valid_address(mod_base):
        return addr_space
    for proc in procs:
        ps_ad = proc.get_process_address_space()
        if ps_ad != None:
            if ps_ad.is_valid_address(mod_base):
                return ps_ad
    return None
