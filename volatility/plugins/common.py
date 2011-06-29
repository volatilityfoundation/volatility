# Volatility
#
# Authors:
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

""" This plugin contains CORE classes used by lots of other plugins """
import volatility.scan as scan
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611

#pylint: disable-msg=C0111

## The following are checks for pool scanners.

class PoolTagCheck(scan.ScannerCheck):
    """ This scanner checks for the occurance of a pool tag """
    def __init__(self, address_space, tag = None, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.tag = tag

    def skip(self, data, offset):
        try:
            nextval = data.index(self.tag, offset + 1)
            return nextval - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset

    def check(self, offset):
        data = self.address_space.read(offset, len(self.tag))
        return data == self.tag

class CheckPoolSize(scan.ScannerCheck):
    """ Check pool block size """
    def __init__(self, address_space, condition = (lambda x: x == 8), **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.condition = condition

    def check(self, offset):
        pool_hdr = obj.Object('_POOL_HEADER', vm = self.address_space,
                             offset = offset - 4)

        block_size = pool_hdr.BlockSize.v()

        return self.condition(block_size * 8)

class CheckPoolType(scan.ScannerCheck):
    """ Check the pool type """
    def __init__(self, address_space, paged = False,
                 non_paged = False, free = False, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.non_paged = non_paged
        self.paged = paged
        self.free = free

    def check(self, offset):
        pool_hdr = obj.Object('_POOL_HEADER', vm = self.address_space,
                             offset = offset - 4)

        ptype = pool_hdr.PoolType.v()

        if self.non_paged and (ptype % 2) == 1:
            return True

        if self.free and ptype == 0:
            return True

        if self.paged and (ptype % 2) == 0 and ptype > 0:
            return True

class CheckPoolIndex(scan.ScannerCheck):
    """ Checks the pool index """
    def __init__(self, address_space, value = 0, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.value = value

    def check(self, offset):
        pool_hdr = obj.Object('_POOL_HEADER', vm = self.address_space,
                             offset = offset - 4)

        return pool_hdr.PoolIndex == self.value
