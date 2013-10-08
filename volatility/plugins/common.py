# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

""" This plugin contains CORE classes used by lots of other plugins """
import volatility.scan as scan
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.commands as commands

#pylint: disable-msg=C0111

class AbstractWindowsCommand(commands.Command):
    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'unknown') == 'windows'

def pool_align(vm, object_name, align):
    """Returns the size of the object accounting for pool alignment."""
    size_of_obj = vm.profile.get_obj_size(object_name)

    # Size is rounded to pool alignment
    extra = size_of_obj % align
    if extra:
        size_of_obj += align - extra

    return size_of_obj

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

        pool_alignment = obj.VolMagic(self.address_space).PoolAlignment.v()

        return self.condition(block_size * pool_alignment)

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

        return ((self.non_paged and pool_hdr.NonPagedPool) or
               (self.free and pool_hdr.FreePool) or
               (self.paged and pool_hdr.PagedPool))

class CheckPoolIndex(scan.ScannerCheck):
    """ Checks the pool index """
    def __init__(self, address_space, value = 0, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.value = value

    def check(self, offset):
        pool_hdr = obj.Object('_POOL_HEADER', vm = self.address_space,
                             offset = offset - 4)

        return pool_hdr.PoolIndex == self.value
