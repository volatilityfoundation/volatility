# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import time
import urlparse
import volatility.addrspace as addrspace

# TODO: Remove this once we no longer support old/broken versions of urlparse (2.6.2)
check = urlparse.urlsplit("firewire://method/0")
urlparse_broken = False
if check[1] != 'method':
  urlparse_broken = True

def FirewireRW(netloc, location):
    if netloc in fw_implementations:
        return fw_implementations[netloc](location)
    return None

class FWRaw1394(object):
    def __init__(self, location):
        locarr = location.split('/')
        self.bus = locarr[0]
        self.node = locarr[1]
        self._node = None

    def is_valid(self):
        """Initializes the firewire implementation"""
        self._node = None
        try:
            h = firewire.Host()
            self._node = h[self.bus][self.node]
            return True, "Valid"
        except IndexError:
            return False, "Firewire node " + str(self.node) + " on bus " + str(self.bus) + " was not accessible"
        except IOError, e:
            return False, "Firewire device IO error - " + str(e)
        return False, "Unknown Error occurred"

    def read(self, addr, length):
        """Reads bytes from the specified address"""
        return self._node.read(addr, length)

    def write(self, addr, buf):
        """Writes buf bytes at addr"""
        return self._node.write(addr, buf)

class FWForensic1394(object):
    def __init__(self, location):
        """Initializes the firewire implementation"""
        self.location = location.strip('/')
        self._bus = forensic1394.Bus()
        self._bus.enable_sbp2()
        self._device = None

    def is_valid(self):
        try:
            time.sleep(2)
            devices = self._bus.devices()
            # FIXME: Base the device off the location rather than hardcoded first remote device
            self._device = devices[int(self.location)]
            # Cetain Firewire cards misreport their maximum request size, notably Ricoh onboard chipsets
            # Uncomment the line below for such broken hardware
            # self._device._request_size = 1024
            if not self._device.isopen():
                self._device.open()
            # The device requires time to settle before it can be used
            return True, "Valid"
        except IOError, e:
            print repr(e)
            return False, "Forensic1394 returned an exception: " + str(e)
        return False, "Unknown Error occurred"

    def read(self, addr, length):
        """Reads bytes from the specified address"""
        return self._device.read(addr, length)

    def write(self, addr, buf):
        """Writes buf bytes at addr"""
        return self._device.write(addr, buf)

class FirewireAddressSpace(addrspace.BaseAddressSpace):
    """A physical layer address space that provides access via firewire"""

    ## We should be *almost* the AS of last resort
    order = 99
    def __init__(self, base, config, **kargs):
        self.as_assert(base == None, 'Must be first Address Space')
        try:
            (scheme, netloc, path, _, _, _) = urlparse.urlparse(config.LOCATION)
            self.as_assert(scheme == 'firewire', 'Not a firewire URN')
            if urlparse_broken:
                if path.startswith('//') and path[2:].find('/') > 0:
                    firstslash = path[2:].find('/')
                    netloc = path[2:firstslash + 2]
                    path = path[firstslash + 3:]
            self._fwimpl = FirewireRW(netloc, path)
        except (AttributeError, ValueError):
            self.as_assert(False, "Unable to parse {0} as a URL".format(config.LOCATION))
        addrspace.BaseAddressSpace.__init__(self, base, config, **kargs)
        self.as_assert(self._fwimpl is not None, "Unable to locate {0} implementation.".format(netloc))
        valid, reason = self._fwimpl.is_valid()
        self.as_assert(valid, reason)

        # We have a list of exclusions because we know that trying to read anything in these sections
        # will cause the target machine to bluescreen
        # Exceptions are in the form (start, length, "Reason")
        self._exclusions = sorted([(0xa0000, 0xfffff - 0xa0000, "Upper Memory Area")])

        self.name = "Firewire using " + str(netloc) + " at " + str(path)
        # We have no way of knowing how big a firewire space is...
        # Set it to the maximum for the moment
        # TODO: Find a way of determining the size safely and reliably from the space itself 
        self.size = 0xFFFFFFFF

    def intervals(self, start, size):
        """Returns a list of intervals, from start of length size, that do not include the exclusions"""
        return self._intervals(sorted(self._exclusions), start, size + start, [])

    def _intervals(self, exclusions, start, end, accumulator):
        """Accepts a sorted list of intervals and a start and end
        
           This will return a list of intervals between start and end
           that does not contain any of the intervals in the list of exclusions.
        """
        if not len(exclusions):
            # We're done
            return accumulator + [(start, end - start)]

        e = exclusions[0]
        estart = e[0]
        eend = e[1] + estart

        # e and range overlap
        if (eend < start or estart > end):
            # Ignore this exclusion
            return self._intervals(exclusions[1:], start, end, accumulator)
        if estart < start:
            if eend < end:
                # Covers the start of the remaining length
                return self._intervals(exclusions[1:], eend, end, accumulator)
            else:
                # Covers the entire remaining area
                return accumulator
        else:
            if eend < end:
                # Covers a section of the remaining length
                return self._intervals(exclusions[1:], eend, end, accumulator + [(start, estart - start)])
            else:
                # Covers the end of the remaining length
                return accumulator + [(start, estart - start)]

    def read(self, offset, length):
        """Reads a specified size in bytes from the current offset
        
           Fills any excluded holes with zeros (so in that sense, similar to zread)
        """
        ints = self.intervals(offset, length)
        output = "\x00" * length
        try:
            for i in ints:
                datstart, datlen = i[0], i[1]
                if datlen > 0:
                    # node.read won't work on 0 byte
                    readdata = self._fwimpl.read(datstart, datlen)
                    # I'm not sure why, but sometimes readdata comes out longer than the requested size
                    # We just truncate it to the right length
                    output = output[:datstart - offset] + readdata[:datlen] + output[(datstart - offset) + datlen:]
        except IOError, e:
            print repr(e)
            raise RuntimeError("Failed to read from firewire device")
        self.as_assert(len(output) == length, "Firewire read lengths failed to match")
        return output

    def zread(self, offset, length):
        """ Delegate padded reads to normal read, since errors reading 
            the physical address should probably be reported back to the user
        """
        return self.read(offset, length)

    def write(self, offset, data):
        """Writes a specified size in bytes"""
        if not self._config.WRITE:
            return False

        ints = self.intervals(offset, len(data))
        try:
            for i in ints:
                datstart, datlen = i[0], i[1]
                if datlen > 0:
                    self._fwimpl.write(datstart, data[(datstart - offset):(datstart - offset) + datlen])
        except IOError:
            raise RuntimeError("Failed to write to the firewire device")
        return True

    def get_address_range(self):
        """Returns the size of the address range"""
        return [0, self.size - 1]

    def get_available_addresses(self):
        """Returns a list of available addresses"""
        for i in self.intervals(0, self.size):
            yield i

fw_implementations = {}

try:
    import firewire #pylint: disable-msg=F0401
    fw_implementations['raw1394'] = FWRaw1394
except ImportError:
    pass

try:
    import forensic1394 #pylint: disable-msg=F0401
    fw_implementations['forensic1394'] = FWForensic1394
except ImportError:
    pass

if not len(fw_implementations):
    FirewireAddressSpace = None
