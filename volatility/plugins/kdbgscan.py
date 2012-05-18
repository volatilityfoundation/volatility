# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import volatility.obj as obj
import volatility.scan as scan
import volatility.cache as cache
import volatility.plugins.common as common
import volatility.addrspace as addrspace
import volatility.registry as registry
import volatility.utils as utils

class MultiStringFinderCheck(scan.ScannerCheck):
    """ Checks for multiple strings per page """

    def __init__(self, address_space, needles = None):
        scan.ScannerCheck.__init__(self, address_space)
        if not needles:
            needles = []
        self.needles = needles
        self.maxlen = 0
        for needle in needles:
            self.maxlen = max(self.maxlen, len(needle))
        if not self.maxlen:
            raise RuntimeError("No needles of any length were found for the " + self.__class__.__name__)

    def check(self, offset):
        verify = self.address_space.read(offset, self.maxlen)
        for match in self.needles:
            if verify[:len(match)] == match:
                return True
        return False

    def skip(self, data, offset):
        nextval = len(data)
        for needle in self.needles:
            dindex = data.find(needle, offset + 1)
            if dindex > -1:
                nextval = min(nextval, dindex)
        return nextval - offset

class MultiPrefixFinderCheck(MultiStringFinderCheck):
    """ Checks for multiple strings per page, finishing at the offset """
    def check(self, offset):
        verify = self.address_space.read(offset - self.maxlen, self.maxlen)
        for match in self.needles:
            if verify.endswith(match):
                return True
        return False

class KDBGScanner(scan.BaseScanner):
    checks = [ ]

    def __init__(self, window_size = 8, needles = None):
        oses = set()
        arches = set()
        for needle in needles:
            header = str(needle).split('KDBG')
            arches.add(header[0])
            oses.add('KDBG' + header[1])
        self.checks = [ ("PoolTagCheck", {'tag': "KDBG"}),
                        ("MultiPrefixFinderCheck", {'needles':arches}),
                        ("MultiStringFinderCheck", {'needles':oses})]
        scan.BaseScanner.__init__(self, window_size)

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            # Compensate for KDBG appearing within the searched for structure
            # (0x10 should really be the offset of OwnerTag from with the structure,
            #  however we don't know which profile to read it from, so it's hardwired)
            # NOTE: this will not work correctly for _KDDEBUGGER_DATA32 structures
            #       however they're only necessary for NT or older
            offset = offset - 0x10
            yield offset

class KDBGScan(common.AbstractWindowsCommand):
    """Search for and dump potential KDBG values"""

    @staticmethod
    def register_options(config):
        config.add_option('KDBG', short_option = 'g', default = None, type = 'int',
                          help = "Specify a specific KDBG virtual address")

    @cache.CacheDecorator(lambda self: "tests/kdbgscan/kdbg={0}".format(self._config.KDBG))
    def calculate(self):
        """Determines the address space"""
        profilelist = [ p.__name__ for p in registry.get_plugin_classes(obj.Profile).values() ]

        proflens = {}
        maxlen = 0
        origprofile = self._config.PROFILE
        for p in profilelist:
            self._config.update('PROFILE', p)
            buf = addrspace.BufferAddressSpace(self._config)
            proflens[p] = str(obj.VolMagic(buf).KDBGHeader)
            maxlen = max(maxlen, len(proflens[p]))
        self._config.update('PROFILE', origprofile)

        scanner = KDBGScanner(needles = proflens.values())

        aspace = utils.load_as(self._config, astype = 'any')

        for offset in scanner.scan(aspace):
            val = aspace.read(offset, maxlen + 0x10)
            for l in proflens:
                if val.find(proflens[l]) >= 0:
                    if hasattr(aspace, 'vtop'):
                        yield l, aspace.vtop(offset), offset
                    else:
                        yield l, offset, None

    def render_text(self, outfd, data):
        """Renders the KPCR values as text"""

        outfd.write("Potential KDBG structure addresses (P = Physical, V = Virtual):\n")
        for n, o, v in data:
            if v is not None:
                outfd.write(" _KDBG: V {1:#010x}  ({2})\n".format(o, v, n))
            outfd.write(" _KDBG: P {0:#010x}  ({2})\n".format(o, v, n))
