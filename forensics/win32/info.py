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

#
# Details about the techniques used in this file can be found in 
# the following references:
#   - Opc0de, "Finding some non-exported kernel variables," 
#              http://www.rootkit.com/vault/Opc0de/GetVarXP.pdf 
#   - Alex Ionescu, "Getting Kernel Variables from KdVersionBlock, Part 2," 
#              http://www.rootkit.com/newsread.php?newsid=153
#

from forensics.object import *
from forensics.win32.datetime import system_time

from struct import unpack

kpcr_addr =  0xffdff000
KUSER_SHARED_DATA = 0xFFDF0000

def info_mmpfndatabase64(addr_space, types, addr):
   return read_obj(addr_space, types,
                   ['_KDDEBUGGER_DATA64', 'MmPfnDatabase'], addr)

def info_psactiveprocesshead64(addr_space, types, debug_addr):
   return read_obj(addr_space, types,
                   ['_KDDEBUGGER_DATA64', 'PsActiveProcessHead'], debug_addr)

def info_psactiveprocesshead32(addr_space, types, debug_addr):
   return read_obj(addr_space, types,
                   ['_KDDEBUGGER_DATA32', 'PsActiveProcessHead'], debug_addr)

def info_psloadedmodulelist64(addr_space, types, addr):
   return read_obj(addr_space, types,
                   ['_KDDEBUGGER_DATA64', 'PsLoadedModuleList'], addr)

def info_psloadedmodulelist32(addr_space, types, debug_addr):
   return read_obj(addr_space, types,
                   ['_KDDEBUGGER_DATA32', 'PsLoadedModuleList'], debug_addr)

def info_kdversionblock(addr_space, types, addr):
   return read_obj(addr_space, types,
                   ['_KPCR', 'KdVersionBlock'], addr)

def info_debuggerdatalist(addr_space,types,addr):
   return read_obj(addr_space, types,
                   ['_DBGKD_GET_VERSION64', 'DebuggerDataList'], addr)


def find_psactiveprocesshead(addr_space, types):

    if not addr_space.is_valid_address(kpcr_addr):
        print "Unable to find PsActiveProcessHead"
        return None

    KdVersionBlock = info_kdversionblock(addr_space, types, kpcr_addr)

    if not addr_space.is_valid_address(KdVersionBlock):
        print "Unable to find PsActiveProcessHead"
        return None

    DebuggerDataList = info_debuggerdatalist(addr_space, types, KdVersionBlock)

    if addr_space.is_valid_address(DebuggerDataList):
        current = read_value(addr_space, 'unsigned long', DebuggerDataList)
        PsActiveProcessHead = info_psactiveprocesshead64(addr_space, types, current)

        if not addr_space.is_valid_address(PsActiveProcessHead):
            PsActiveProcessHead = info_psactiveprocesshead32(addr_space, types, KdVersionBlock)

            if not addr_space.is_valid_address(PsActiveProcessHead):
                print "Unable to find PsActiveProcessHead"
                return None
    else:
        PsActiveProcessHead = info_psactiveprocesshead32(addr_space, types, KdVersionBlock)
        if not addr_space.is_valid_address(PsActiveProcessHead):
            print "Unable to find PsActiveProcessHead"
            return None

    return PsActiveProcessHead


def find_psloadedmodulelist(addr_space, types):

    if not addr_space.is_valid_address(kpcr_addr):
        print "Unable to find PsLoadedModuleList"
        return None

    KdVersionBlock = info_kdversionblock(addr_space, types, kpcr_addr)

    if not addr_space.is_valid_address(KdVersionBlock):
        print "Unable to find PsLoadedModuleList"
        return None

    DebuggerDataList = info_debuggerdatalist(addr_space, types, KdVersionBlock)
   
    if addr_space.is_valid_address(DebuggerDataList):
        current = read_value(addr_space, 'unsigned long', DebuggerDataList)
        PsLoadedModuleList = info_psloadedmodulelist64(addr_space, types, current)
        if not addr_space.is_valid_address(PsLoadedModuleList):
            PsLoadedModuleList = info_psloadedmodulelist32(addr_space, types, KdVersionBlock)
            if not addr_space.is_valid_address(PsLoadedModuleList):
                print "Unable to find PsLoadedModuleList"
                return None
    else:
        PsLoadedModuleList = info_psloadedmodulelist32(addr_space, types, KdVersionBlock)
        if not addr_space.is_valid_address(PsLoadedModuleList):
            print "Unable to find PsLoadedModuleList"
            return None

    return PsLoadedModuleList

def find_mmpfndatabase(addr_space, types):

    if not addr_space.is_valid_address(kpcr_addr):
        print "Unable to find MmPfnDatabase"
        return None

    KdVersionBlock = info_kdversionblock(addr_space, types, kpcr_addr)

    if not addr_space.is_valid_address(KdVersionBlock):
        print "Unable to find MmPfnDatabase"
        return None

    DebuggerDataList = info_debuggerdatalist(addr_space, types, KdVersionBlock)

    if addr_space.is_valid_address(DebuggerDataList):
        current = read_value(addr_space, 'unsigned long', DebuggerDataList)
        MmPfnDatabase = info_mmpfndatabase64(addr_space, types, current)

        if not addr_space.is_valid_address(MmPfnDatabase):
            print "Unable to find MmPfnDatabase"
            return None
        else:
            MmPfnDatabase = read_value(addr_space, 'pointer', MmPfnDatabase)
    else:
        print "Unable to find MmPfnDatabase"
        return None


    return MmPfnDatabase 

def find_kddebuggerdatablock(addr_space, types):
    if not addr_space.is_valid_address(kpcr_addr):
        print "Unable to find KdDebuggerDataBlock"
        return None

    KdVersionBlock = info_kdversionblock(addr_space, types, kpcr_addr)

    if not addr_space.is_valid_address(KdVersionBlock):
        print "Unable to find KdDebuggerDataBlock"
        return None

    DebuggerDataList = info_debuggerdatalist(addr_space, types, KdVersionBlock)

    if addr_space.is_valid_address(DebuggerDataList):
        KdDebuggerDataBlock = read_value(addr_space, 'pointer', DebuggerDataList)

        if not addr_space.is_valid_address(KdDebuggerDataBlock):
            print "Unable to find KdDebuggerDataBlock"
            return None
    else:
        print "Unable to find KdDebuggerDataBlock"
        return None

    return KdDebuggerDataBlock 

def find_suitemask(addr_space, types):
    return read_obj(addr_space, types,
               ['_KUSER_SHARED_DATA', 'SuiteMask'],KUSER_SHARED_DATA )

def find_systemtime(addr_space, types):
    return system_time(addr_space, types, KUSER_SHARED_DATA)
