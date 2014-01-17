# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

import volatility.exceptions as exceptions
import volatility.registry as registry
import volatility.addrspace as addrspace
import volatility.debug as debug
import socket
import itertools

#pylint: disable-msg=C0111

def load_as(config, astype = 'virtual', **kwargs):
    """Loads an address space by stacking valid ASes on top of each other (priority order first)"""

    base_as = None
    error = exceptions.AddrSpaceError()

    # Start off requiring another round    
    found = True
    ## A full iteration through all the classes without anyone
    ## selecting us means we are done:
    while found:
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

# Compensate for Windows python not supporting socket.inet_ntop and some
# Linux systems (i.e. OpenSuSE 11.2 w/ Python 2.6) not supporting IPv6. 

def inet_ntop(address_family, packed_ip):

    def inet_ntop4(packed_ip):
        if not isinstance(packed_ip, str):
            raise TypeError("must be string, not {0}".format(type(packed_ip)))
        if len(packed_ip) != 4:
            raise ValueError("invalid length of packed IP address string")
        return "{0}.{1}.{2}.{3}".format(*[ord(x) for x in packed_ip])

    def inet_ntop6(packed_ip):
        if not isinstance(packed_ip, str):
            raise TypeError("must be string, not {0}".format(type(packed_ip)))
        if len(packed_ip) != 16:
            raise ValueError("invalid length of packed IP address string")

        words = []
        for i in range(0, 16, 2):
            words.append((ord(packed_ip[i]) << 8) | ord(packed_ip[i + 1]))

        # Replace a run of 0x00s with None
        numlen = [(k, len(list(g))) for k, g in itertools.groupby(words)]
        max_zero_run = sorted(sorted(numlen, key = lambda x: x[1], reverse = True), key = lambda x: x[0])[0]
        words = []
        for k, l in numlen:
            if (k == 0) and (l == max_zero_run[1]) and not (None in words):
                words.append(None)
            else:
                for i in range(l):
                    words.append(k)

        # Handle encapsulated IPv4 addresses
        encapsulated = ""
        if (words[0] is None) and (len(words) == 3 or (len(words) == 4 and words[1] == 0xffff)):
            words = words[:-2]
            encapsulated = inet_ntop4(packed_ip[-4:])
        # If we start or end with None, then add an additional :
        if words[0] is None:
            words = [None] + words
        if words[-1] is None:
            words += [None]
        # Join up everything we've got using :s
        return ":".join(["{0:x}".format(w) if w is not None else "" for w in words]) + encapsulated

    if address_family == socket.AF_INET:
        return inet_ntop4(packed_ip)
    elif address_family == socket.AF_INET6:
        return inet_ntop6(packed_ip)
    raise socket.error("[Errno 97] Address family not supported by protocol")

def iterfind(data, string):
    """This function is called by the search_process_memory() 
    method of windows, linux, and mac process objects"""

    offset = data.find(string, 0)
    while offset >= 0:
        yield offset
        offset = data.find(string, offset + len(string))
