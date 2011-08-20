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

import volatility.registry as registry
import volatility.addrspace as addrspace
import volatility.debug as debug

#pylint: disable-msg=C0111

class classproperty(property):
    def __get__(self, cls, owner):
        # We don't think pylint knows what it's talking about here
        return self.fget.__get__(None, owner)() #pylint: disable-msg=E1101

def load_as(config, astype = 'virtual', **kwargs):
    """Loads an address space by stacking valid ASes on top of each other (priority order first)"""

    base_as = None
    error = AddrSpaceError()
    while 1:
        debug.debug("Voting round")
        found = False
        for cls in registry.AS_CLASSES.classes:
            debug.debug("Trying {0} ".format(cls))
            try:
                base_as = cls(base_as, config, astype = astype, **kwargs)
                debug.debug("Succeeded instantiating {0}".format(base_as))
                found = True
                break
            except addrspace.ASAssertionError, e:
                debug.debug("Failed instantiating {0}: {1}".format(cls.__name__, e), 2)
                error.append_reason(cls.__name__, e)
                continue
            except Exception, e:
                debug.debug("Failed instantiating (exception): {0}".format(e))
                error.append_reason(cls.__name__ + " - EXCEPTION", e)
                continue

        ## A full iteration through all the classes without anyone
        ## selecting us means we are done:
        if not found:
            break

    if not isinstance(base_as, addrspace.AbstractVirtualAddressSpace) and (astype == 'virtual'):
        base_as = None

    if base_as is None:
        raise error

    return base_as

class VolatilityException(Exception):
    """Generic Volatility Specific exception, to help differentiate from other exceptions"""
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class AddrSpaceError(VolatilityException):
    """Address Space Exception, so we can catch and deal with it in the main program"""
    def __init__(self):
        self.reasons = []
        VolatilityException.__init__(self, "No suitable address space mapping found")

    def append_reason(self, driver, reason):
        self.reasons.append((driver, reason))

    def __str__(self):
        result = VolatilityException.__str__(self) + "\nTried to open image as:\n"
        for k, v in self.reasons:
            result += " {0}: {1}\n".format(k, v)

        return result

class CacheRelativeURLException(VolatilityException):
    """Exception for gracefully not saving Relative URLs in the cache"""

def Hexdump(data, width=16):
    """ Hexdump function shared by various plugins """
    for offset in xrange(0, len(data), width):
        row_data = data[offset:offset+width]
        translated_data = [x if ord(x) < 100 and ord(x) > 32 else "." for x in row_data]
        hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])
    
        yield offset, hexdata, translated_data

