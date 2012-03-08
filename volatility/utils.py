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

import volatility.exceptions as exceptions
import volatility.registry as registry
import volatility.addrspace as addrspace
import volatility.debug as debug

#pylint: disable-msg=C0111

def load_as(config, astype = 'virtual', **kwargs):
    """Loads an address space by stacking valid ASes on top of each other (priority order first)"""

    base_as = None
    error = exceptions.AddrSpaceError()
    while 1:
        debug.debug("Voting round")
        found = False
        for cls in sorted(registry.get_plugin_classes(addrspace.BaseAddressSpace).values(),
                          key = lambda x: x.order if hasattr(x, 'order') else 10):
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

def Hexdump(data, width = 16):
    """ Hexdump function shared by various plugins """
    for offset in xrange(0, len(data), width):
        row_data = data[offset:offset + width]
        translated_data = [x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
        hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

        yield offset, hexdata, translated_data
