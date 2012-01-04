# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Copyright (C) 2004,2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

   Alias for all address spaces 

"""

#pylint: disable-msg=C0111

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
    if registry.PROFILES:
        try:
            registry.PROFILES[value]
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
        self._config = config
        self.profile = self._set_profile(config.PROFILE)

    @staticmethod
    def register_options(config):
        ## By default load the profile that the user asked for
        config.add_option("PROFILE", default = 'WinXPSP2x86', type = 'str',
                          nargs = 1, action = "callback", callback = check_valid_profile,
                          help = "Name of the profile to load")

        config.add_option("LOCATION", default = None, short_option = 'l',
                          help = "A URN location from which to load an address space")

    def get_config(self):
        """Returns the config object used by the vm for use in other vms"""
        return self._config

    def _set_profile(self, profile_name):
        ## Load the required profile
        try:
            ret = PROFILES[profile_name]
        except KeyError:
            try:
                ret = registry.PROFILES[profile_name]()
                PROFILES[profile_name] = ret
            except KeyError:
                raise ASAssertionError, "Invalid profile " + profile_name + " selected"
        if not self.is_valid_profile(ret):
            raise ASAssertionError, "Incompatible profile " + profile_name + " selected"
        return ret

    def is_valid_profile(self, profile):
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
        return self.__class__ == other.__class__ and \
               self.profile == other.profile and self.base == other.base

    def __ne__(self, other):
        return not self == other

    def read(self, addr, length):
        """ Read some date from a certain offset """

    def get_available_addresses(self):
        """ Return a generator of address ranges as (offset, size) covered by this AS """
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

class AbstractVirtualAddressSpace(BaseAddressSpace):
    """Base Ancestor for all Virtual address spaces, as determined by astype"""
    def __init__(self, base, config, astype = 'virtual', *args, **kwargs):
        BaseAddressSpace.__init__(self, base, config, astype = astype, *args, **kwargs)
        self.as_assert(astype == 'virtual' or astype == 'any', "User requested non-virtual AS")

    def vtop(self, vaddr):
        raise NotImplementedError("This is a virtual class and should not be referenced directly")

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

    def write(self, addr, data):
        if not self._config.WRITE:
            return False
        self.data = self.data[:addr] + data + self.data[addr + len(data):]
        return True

    def get_available_addresses(self):
        yield (self.base_offset, len(self.data))
