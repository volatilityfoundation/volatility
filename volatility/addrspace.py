# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# Original Source:
# Copyright (C) 2004,2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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
@author:       AAron Walters
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.com
@organization: Volatility Foundation

   Alias for all address spaces 

"""

#pylint: disable-msg=C0111

import fractions
import volatility.obj as obj
import volatility.registry as registry
import volatility.debug as debug

## Make sure the profiles are cached so we only parse it once. This is
## important since it allows one module to update the profile for
## another module.
PROFILES = {}

class ASAssertionError(AssertionError):

    def __init__(self, *args, **kwargs):
        AssertionError.__init__(self, *args, **kwargs)

def check_valid_profile(option, _opt_str, value, parser):
    """Checks to make sure the selected profile is valid"""
    # PROFILES may not have been created yet,
    # but the callback should get called once it has
    # during the final parse of the config options
    profs = registry.get_plugin_classes(obj.Profile)
    if profs:
        try:
            profs[value]
        except KeyError:
            debug.error("Invalid profile " + value + " selected")
        setattr(parser.values, option.dest, value)

class BaseAddressSpace(object):
    """ This is the base class of all Address Spaces. """
    def __init__(self, base, config, *_args, **_kwargs):
        """ base is the AS we will be stacking on top of, opts are
        options which we may use.
        """
        self.base = base
        self.name = "Unnamed AS"
        self._config = config
        self.profile = self._set_profile(config.PROFILE)

    @staticmethod
    def register_options(config):
        ## By default load the profile that the user asked for
        config.add_option("PROFILE", default = "WinXPSP2x86", type = 'str',
                          nargs = 1, action = "callback", callback = check_valid_profile,
                          help = "Name of the profile to load")

        config.add_option("LOCATION", default = None, short_option = 'l',
                          help = "A URN location from which to load an address space")

    def get_config(self):
        """Returns the config object used by the vm for use in other vms"""
        return self._config

    def _set_profile(self, profile_name):
        ## Load the required profile
        if profile_name == None:
            raise ASAssertionError, "You must set a profile!"
        if profile_name in PROFILES:
            ret = PROFILES[profile_name]
        else:
            profs = registry.get_plugin_classes(obj.Profile)
            if profile_name in profs:
                ret = profs[profile_name]()
                PROFILES[profile_name] = ret
            else:
                raise ASAssertionError, "Invalid profile " + profile_name + " selected"
        if not self.is_valid_profile(ret):
            raise ASAssertionError, "Incompatible profile " + profile_name + " selected"
        return ret

    def is_valid_profile(self, profile): #pylint: disable-msg=W0613
        """Determines whether a selected profile is compatible with this address space"""
        return True

    def as_assert(self, assertion, error = None):
        """Duplicate for the assert command (so that optimizations don't disable them)
        
           It had to be called as_assert, since assert is a keyword
        """
        if not assertion:
            if error == None:
                error = "Instantiation failed for unspecified reason"
            raise ASAssertionError, error

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.profile == other.profile and self.base == other.base)

    def __ne__(self, other):
        return not self == other

    def read(self, addr, length):
        """ Read some data from a certain offset """

    def zread(self, addr, length):
        """ Read data from a certain offset padded with \x00 where data is not available """

    def get_available_addresses(self):
        """ Return a generator of address ranges as (offset, size) covered by this AS sorted by offset.

            The address ranges produced must be disjoint (no overlaps) and not be continuous
            (there must be a gap between two ranges).
        """
        raise StopIteration

    def is_valid_address(self, _addr):
        """ Tell us if the address is valid """
        return True

    def write(self, _addr, _buf):
        if not self._config.WRITE:
            return False
        raise NotImplementedError("Write support for this type of Address Space has not been implemented")

    def __getstate__(self):
        """ Serialise this address space efficiently """
        ## FIXME: Note that types added/overridden in the config.PROFILE may bleed through
        ## into other plugins from the cache.  This needs fixing.
        return dict(name = self.__class__.__name__, base = self.base, config = self._config)

    def __setstate__(self, state):
        self.__init__(**state)

    @classmethod
    def address_mask(cls, addr):
        """Masks an address value for this address space"""
        return addr

    @classmethod
    def address_compare(cls, a, b):
        """Compares two addresses, a and b, and return -1 if a is less than b, 0 if they're equal and 1 if a is greater than b"""
        return cmp(cls.address_mask(a), cls.address_mask(b))

    @classmethod
    def address_equality(cls, a, b):
        """Compare two addresses and returns True if they're the same, or False if they're not"""
        return cls.address_compare(a, b) == 0

    def physical_space(self):
        """Return the underlying physical layer, if there is one. 

        This cycles through the base address spaces and returns 
        the first one that's not an ancestor of a virtual space. 
        """
        b = self.base

        while b:
            if not isinstance(b, AbstractVirtualAddressSpace):
                return b
            b = b.base

        return self

class AbstractDiscreteAllocMemory(BaseAddressSpace):
    """A class based on memory stored as discrete allocations.
    """
    minimum_size = None
    alignment_gcd = None

    def __init__(self, base, config, *args, **kwargs):
        BaseAddressSpace.__init__(self, base, config, *args, **kwargs)

    def translate(self, vaddr):
        raise NotImplementedError("This is an abstract method and should not be referenced directly")

    def get_available_allocs(self):
        """A generator that returns (addr, size) for each of the virtual addresses present, sorted by offset"""
        raise NotImplementedError("This is an abstract method and should not be referenced directly")

    def calculate_alloc_stats(self):
        """Calculates the minimum_size and alignment_gcd to determine "virtual allocs" when read lengths of data
           It's particularly important to cast all numbers to ints, since they're used a lot and object take effort to reread.
        """
        available_allocs = list(self.get_available_allocs())

        self.minimum_size = int(min([size for _, size in available_allocs]))
        accumulator = self.minimum_size
        for start, _ in available_allocs:
            if accumulator is None and start > 1:
                accumulator = start
            if accumulator and start > 0:
                accumulator = fractions.gcd(accumulator, start)
        self.alignment_gcd = int(accumulator)
        # Pick an arbitrary cut-off that'll lead to too many reads
        if self.alignment_gcd < 0x4:
            debug.warning("Alignment of " + self.__class__.__name__ + " is too small, plugins will be extremely slow")

    def _read(self, addr, length, pad = False):
        """Reads length bytes at the address addr

           If pad is False, this can return None if some of the address space is empty
           If pad is True, any read errors result in "\x00" bytes filling the missing read locations
        """

        if not self.alignment_gcd or not self.minimum_size:
            self.calculate_alloc_stats()

        position = addr
        remaining = length
        buff = []
        lenbuff = 0
        read = self.base.zread if pad else self.base.read

        # For each allocation...
        while remaining > 0:
            # Determine whether we're within an alloc or not
            alloc_remaining = (self.alignment_gcd - (addr % self.alignment_gcd))
            # Try to jump out early
            paddr = self.translate(position)
            datalen = min(remaining, alloc_remaining)
            if paddr is None:
                if not pad:
                    return None
                buff.append("\x00" * datalen)
                lenbuff += datalen
            else:
                # This accounts for a special edge case
                # when the address is valid in this address space
                # but not in the underlying (base) address space.
                # We have seen this happen with IA32/FileAddr

                if self.base.is_valid_address(paddr):
                    data = read(paddr, datalen)
                else:
                    if not pad:
                        return obj.NoneObject("Could not read_chunks from addr " + hex(position) + " of size " + hex(datalen))
                    data = "\x00" * datalen
                buff.append(data)
                lenbuff += len(data)
            position += datalen
            remaining -= datalen
            assert (addr + length == position + remaining), "Address + length != position + remaining (" + hex(addr + length) + " != " + hex(position + remaining) + ") in " + self.base.__class__.__name__
            assert (position - addr == lenbuff), "Position - address != len(buff) (" + str(position - addr) + " != " + str(lenbuff) + ") in " + self.base.__class__.__name__
        return "".join(buff)

    def read(self, addr, length):
        '''
        This method reads 'length' bytes from the specified 'addr'.
        If any range is unavailable it returns None.
        '''
        return self._read(addr, length, False)

    def zread(self, addr, length):
        '''
        This method reads 'length' bytes from the specified 'addr'.
        If any range is unavailable it pads the region with zeros.
        '''
        return self._read(addr, length, True)

class AbstractRunBasedMemory(AbstractDiscreteAllocMemory):
    """A class based on memory stored as separate segments.

       @var runs: Stores an ordered list of the segments or runs
                  A run is a tuple of (input/domain/virtual address, output/range/physical address, size of segment)
    """

    def __init__(self, base, config, *args, **kwargs):
        AbstractDiscreteAllocMemory.__init__(self, base, config, *args, **kwargs)
        self.runs = []
        self.header = None

    def get_runs(self):
        """Get the memory block info"""
        return self.runs

    def get_header(self):
        """Get the header info"""
        return self.header

    def translate(self, addr):
        """Find the offset in the file where a memory address can be found.

        @param addr: a memory address
        """
        for input_addr, output_addr, length in self.runs:
            if addr >= input_addr and addr < input_addr + length:
                return output_addr + (addr - input_addr)
            # Since runs are in order, we can bail out early if we're
            # looking for something before the start of the current one
            if addr < input_addr:
                return None

        return None

    def get_available_allocs(self):
        """Get a list of accessible physical memory regions"""
        for input_addr, _, length in self.runs:
            yield input_addr, length

    def get_available_addresses(self):
        """Get a list of physical memory runs"""
        # Since runs are in order and not contiguous
        # we can reuse the output from available_allocs
        return self.get_available_allocs()

    def is_valid_address(self, phys_addr):
        """Check if a physical address is in the file.

        @param phys_addr: a physical address
        """
        return self.translate(phys_addr) is not None

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
        # Runs must not be empty
        (input_address, _, length) = self.runs[-1]
        size = input_address + length
        (start, _, _) = self.runs[0]
        return [start, size]

    def write(self, phys_addr, buf):
        """This is mostly for support of raw2dmp so that 
        it can modify the kernel CONTEXT after the crash
        dump has been written to disk"""

        if not self._config.WRITE:
            return False

        file_addr = self.translate(phys_addr)

        if file_addr is None:
            return False

        return self.base.write(file_addr, buf)

class AbstractVirtualAddressSpace(AbstractDiscreteAllocMemory):
    """Base Ancestor for all Virtual address spaces, as determined by astype"""
    def __init__(self, base, config, astype = 'virtual', *args, **kwargs):
        AbstractDiscreteAllocMemory.__init__(self, base, config, astype = astype, *args, **kwargs)
        self.as_assert(astype == 'virtual' or astype == 'any', "User requested non-virtual AS")

    def vtop(self, vaddr):
        raise NotImplementedError("This is an abstract method and should not be referenced directly")

    def translate(self, vaddr):
        return self.vtop(vaddr)

## This is a specialised AS for use internally - Its used to provide
## transparent support for a string buffer so types can be
## instantiated off the buffer.
class BufferAddressSpace(BaseAddressSpace):
    def __init__(self, config, base_offset = 0, data = '', **kwargs):
        BaseAddressSpace.__init__(self, None, config, **kwargs)
        self.fname = "Buffer"
        self.data = data
        self.base_offset = base_offset

    def assign_buffer(self, data, base_offset = 0):
        self.base_offset = base_offset
        self.data = data

    def is_valid_address(self, addr):
        return not (addr < self.base_offset or addr > self.base_offset + len(self.data))

    def read(self, addr, length):
        offset = addr - self.base_offset
        return self.data[offset: offset + length]

    def zread(self, addr, length):
        return self.read(addr, length)

    def write(self, addr, data):
        if not self._config.WRITE:
            return False
        self.data = self.data[:addr] + data + self.data[addr + len(data):]
        return True

    def get_available_addresses(self):
        yield (self.base_offset, len(self.data))
