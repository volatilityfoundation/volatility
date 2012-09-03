# Volatility
#
# Authors:
# attc - atcuno@gmail.com
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
import volatility.addrspace as addrspace

lime_types = {

 'lime_header': [ 0x20, {
    'magic':     [0x0, ['unsigned int']],
    'version':   [0x4, ['unsigned int']],
    'start':     [0x8, ['unsigned long long']],
    'end':       [0x10, ['unsigned long long']],
    'reversed':  [0x18, ['unsigned long long']],
}],
}

class LimeTypes(obj.ProfileModification):

    def modification(self, profile):

        profile.vtypes.update(lime_types)

class segment(object):

    def __init__(self, start, end, offset):

        self.start  = start
        self.end    = end
        self.offset = offset

class LimeAddressSpace(addrspace.BaseAddressSpace):
    """ 
    Address space for Lime 
    """
    order = 2
    cache = False
    pae = False
    checkname = 'LimeValidAS'

    def __init__(self, base, config, *args, **kwargs):
        self.as_assert(base, "lime: need base")

        addrspace.BaseAddressSpace.__init__(self, base, config, *args, **kwargs)

        sig = base.read(0, 4)

        self.as_assert(sig == '\x45\x4D\x69\x4c' or sig == '\x4c\x69\x4d\x45', "Invalid Lime header signature")
        
        self.addr_cache = {}
        self.segs = []
        self.parse_lime()

    def parse_lime(self):
        # get the segments
        self.segs = []

        offset = 0

        header = obj.Object("lime_header", offset = offset, vm = self.base)

        while header.magic.v() == 0x4c694d45:

            #print "new segment at %x end %x size: %d offset %d | %x" % (header.start, header.end, header.end - header.start, offset, offset)
            seg = segment(header.start, header.end, offset + self.profile.get_obj_size("lime_header"))
            self.segs.append(seg)

            seglength = header.end - header.start

            offset = offset + seglength + 1 + self.profile.get_obj_size("lime_header")

            header = obj.Object("lime_header", offset = offset, vm = self.base)

    def read(self, addr, length):
        return self.__read_bytes(addr, length)

    def zread(self, addr, length):
        return self.__read_bytes(addr, length, True)
    
    def __read_bytes(self, addr, length, pad = False):
        firstram = self.segs[0].start

        if addr < firstram:
            addr = firstram + addr

        key = "{0:d}:{1:d}".format(addr, length)

        if key in self.addr_cache:
            return self.addr_cache[key]

        (_, where) = self.__get_offset(addr)
        
        ret = self.base.read(where, length)

        self.addr_cache[key] = ret
        
        return ret        

    def __get_offset(self, addr):
        for seg in self.segs:
            if seg.start <= addr <= seg.end:

                delta = addr - seg.start

                where = seg.offset + delta

                # find offset into seg and return place inside file
                ret = [addr, where]
                
                return ret

        return None

    # returns a tuple of (start of segment, size of segment) for each segment
    # we do not need special logic to ensure multiple tuples aren't contiguos
    # because lime only creates segments for non-contig RAM sections
    def get_available_addresses(self):
        for seg in self.segs:

            seglength = seg.end - seg.start

            yield (seg.start, seglength)

    def is_valid_address(self, addr):
        return self.__get_offset(addr) != None
