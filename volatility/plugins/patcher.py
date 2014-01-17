# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import sys
import timeit
import binascii
import xml.etree.cElementTree as etree
import volatility.commands as commands
import volatility.debug as debug
import volatility.utils as utils
PAGESIZE = 4096

#XML Example file format
#
#<patchfile>
#  <patchinfo method="pagescan">
#    <constraints>
#      <match offset="[offset within page]">DEADBEEFC0FFEE</match>
#      ...
#    </constraints>
#    <patches>
#      <patch offset="[offset within page]">BEEFF00DEE</match>
#    </patches>
#    ...
#  </patchinfo>
#</patchfile>

class MultiPageScanner(object):
    """Scans a page at a time through the address space
    
       Designed to minimize reads/writes to the address space
    """
    def __init__(self, patchers, full = False):
        self.patchers = list(patchers)
        self.maxlen = 0
        self.remove_patchers = not full

    def use_fullpage(self, address_space):
        """Calibrate the scanner to ensure fastest speed"""
        # Define the calibration functions
        timeit_fullpage = lambda: list(self.scan_page(address_space, 0, True))
        timeit_nonfullpage = lambda: list(self.scan_page(address_space, 0, False))

        with_fullpage = timeit.repeat(timeit_fullpage, number = 100)
        without_fullpage = timeit.repeat(timeit_nonfullpage, number = 100)
        return min(with_fullpage) < min(without_fullpage)

    def scan(self, address_space, outfd):
        """Scans through the pages"""
        page_offset = 0

        sys.stdout.write("Calibrating for speed: ")
        sys.stdout.flush()
        fullpage = self.use_fullpage(address_space)
        if fullpage:
            sys.stdout.write("Reading full pages\n")
        else:
            sys.stdout.write("Reading patch locations per page\n")
        sys.stdout.flush()

        done = False
        while address_space.is_valid_address(page_offset + PAGESIZE) and not done:
            sys.stdout.write("\rScanning: {0:08X}".format(page_offset))
            sys.stdout.flush()

            # Run through any patchers that didn't fail
            for patcher in self.scan_page(address_space, page_offset, fullpage):
                outfd.write("\rPatching {0} at page {1:x}\n".format(patcher.get_name(), page_offset))
                patcher.patch(address_space, page_offset)
                if self.remove_patchers:
                    self.patchers.remove(patcher)
                    # Stop if we've got nothing left to look for
                    if not len(self.patchers):
                        done = True

            # Jump to the next page
            page_offset += PAGESIZE
        sys.stdout.write("\n")

    def scan_page(self, address_space, page_offset, fullpage = False):
        """Runs through patchers for a single page"""
        if fullpage:
            pagedata = address_space.read(page_offset, PAGESIZE)

        for patcher in self.patchers:
            for offset, data in patcher.get_constraints():
                if fullpage:
                    testdata = pagedata[offset:offset + len(data)]
                else:
                    testdata = address_space.read(page_offset + offset, len(data))
                if data != testdata:
                    break
            else:
                yield patcher

class PatcherObject(object):
    """Simple object to hold patching data"""
    def __init__(self, name):
        self.name = name
        self.patches = set()
        self.constraints = set()

    def add_constraint(self, offset, data):
        """Adds a constraint to the constraintlist"""
        # Ensure that all offsets are within PAGESIZE
        self.constraints.add((offset % PAGESIZE, data))

    def add_patch(self, offset, patch):
        """Adds a patch to the patchlist"""
        # Ensure that all offsets are within PAGESIZE
        self.patches.add((offset % PAGESIZE, patch))

    def patch(self, addr_space, page_offset):
        """Writes to the address space"""
        result = True
        for offset, patch, in self.patches:
            result = result and addr_space.write(page_offset + offset, patch)
        return result

    def get_patches(self):
        """Returns the list of patches for this patcher"""
        return self.patches

    def get_constraints(self):
        return self.constraints

    def get_name(self):
        """Returns the name of the patcher"""
        return self.name

class Patcher(commands.Command):
    """Patches memory based on page scans"""
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option('XML-INPUT', short_option = 'x',
                  help = 'Input XML file for patching binaries')

    def calculate(self):
        """Calculates the patchers"""
        addr_space = utils.load_as(self._config, astype = 'physical')
        scanner = MultiPageScanner(self.parse_patchfile())
        return scanner, addr_space

    def render_text(self, outfd, data):
        """Renders the text and carries out the patching"""
        scanner, addr_space = data
        scanner.scan(addr_space, outfd)

    def get_offset(self, tag):
        """Returns the offset from a tag"""
        offset = tag.get('offset', None)
        if not offset:
            return None
        base = 10
        if offset.startswith('0x'):
            offset = offset[2:]
            base = 16
        return int(offset, base)

    def parse_patchfile(self):
        """Parses the patch XML data"""
        if not self._config.WRITE:
            print "Warning: WRITE support not enabled, no patching will occur"

        if self._config.XML_INPUT is None:
            debug.error("No XML input file was specified")
        try:
            root = etree.parse(self._config.XML_INPUT).getroot()
        except SyntaxError, e:
            debug.error("XML input file was improperly formed: " + str(e))

        for element in root:
            if element.tag == 'patchinfo':
                if element.get('method', 'nomethod') == 'pagescan':
                    patcher = PatcherObject(element.get('name', 'Unlabelled'))
                    constraints = None
                    for tag in element:
                        if tag.tag == 'constraints':
                            constraints = tag
                        if tag.tag == 'patches':
                            patches = tag
                    if constraints is None:
                        debug.error("Patch input file does not contain any valid constraints")

                    # Parse the patches section
                    for tag in patches:
                        if tag.tag == 'setbytes':
                            offset = self.get_offset(tag)
                            data = binascii.a2b_hex(tag.text)
                            if offset is not None and len(data):
                                patcher.add_patch(offset, data)
                    if not len(patcher.get_patches()):
                        # No patches, no point adding this
                        break

                    # Parse the constraints section
                    for c in constraints:
                        if c.tag == 'match':
                            offset = self.get_offset(c)
                            data = binascii.a2b_hex(c.text)
                            if offset is not None and len(data):
                                patcher.add_constraint(offset, data)
                    yield patcher
                else:
                    debug.error("Unsupported patchinfo method " + element.method)
