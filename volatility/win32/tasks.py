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
from bisect import bisect_right

def get_kdbg(addr_space):
    """A function designed to return the KDBG structure from 
    an address space. First we try scanning for KDBG and if 
    that fails, we try scanning for KPCR and bouncing back to
    KDBG from there. Please note the backup method only works
    on x86.

    Also note, both the primary and backup methods rely on the 
    4-byte KDBG.Header.OwnerTag. If someone overwrites this 
    value, then neither method will succeed. The same is true 
    even if a user specifies --kdbg, because we check for the 
    OwnerTag even in that case. 
    """

    kdbgo = obj.VolMagic(addr_space).KDBG.v()

    kdbg = obj.Object("_KDDEBUGGER_DATA64", offset = kdbgo, vm = addr_space)

    if kdbg.is_valid():
        return kdbg

    # Fall back to finding it via the KPCR
    kpcr = obj.Object("_KPCR", offset = obj.VolMagic(addr_space).KPCR.v(), vm = addr_space)

    kdbg = kpcr.get_kdbg()

    if kdbg.is_valid():
        return kdbg

    return obj.NoneObject("KDDEBUGGER structure not found using either KDBG signature or KPCR pointer")

def pslist(addr_space):
    """ A Generator for _EPROCESS objects """

    for p in get_kdbg(addr_space).processes():
        yield p

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

def find_module(modlist, mod_addrs, addr):
    """Uses binary search to find what module a given address resides in.

    This is much faster than a series of linear checks if you have
    to do it many times. Note that modlist and mod_addrs must be sorted
    in order of the module base address."""

    pos = bisect_right(mod_addrs, addr) - 1
    if pos == -1:
        return None
    mod = modlist[mod_addrs[pos]]

    if (addr >= mod.DllBase.v() and
        addr < mod.DllBase.v() + mod.SizeOfImage.v()):
        return mod
    else:
        return None
