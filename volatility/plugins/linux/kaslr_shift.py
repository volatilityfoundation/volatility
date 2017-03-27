# Volatility
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
@author:       Bastian Neuburger
@license:      GNU General Public License 2.0
@contact:      bastian.neuburger@gmail.com
@organization:
"""

import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common
import volatility.plugins.overlays.linux.linux as linux_overlay
import re
import volatility.debug as debug
from operator import attrgetter


def find_key(d, value):
    """Searches for a leaf in a nested dictionary and returns the path taken"""
    for k, v in d.items():
        if isinstance(v, dict):
            p = find_key(v, value)
            if p:
                return [k] + p
        elif value.match(v):
            return [k]

# Monkey patch generate_suggestions for VolatilityLinuxIntelValidAS,
# since the default method will yield False in case of KASLR


def generate_suggestions_valid_as(self):
    yield True

# Monkey patch to retrieve all non-zero entries from a Page Map/
# Page Directory Pointer Table/Page Directory/Page Table and
# their index.
# It will not retrieve any large page entries, since those are
# irrelevant for this plugin.


def get_nonzero_entries(self, phys_address):
    # Align physical address to 4096 byte page
    base = phys_address & 0xffffffffff000
    retval = {}
    for i in range(0, 512):
        paddress = i * 8 + base
        value = self.read_long_long_phys(paddress)

        # Ignore the entry if it points to 1 GB or 2 MB page.
        # For the purpose of this plugin we are only interested
        # in "normal" 4096 byte pages
        if self.page_size_flag(value):
            value = 0

        if value == 0:
            continue
        else:
            retval[i] = value

    return retval


def pdpte_index(self, vaddr):
    return (vaddr >> 30) & (512 - 1)


def reverse(string):
    begin = 0
    end = len(string) - 1
    strlist = [i for i in string]
    while(begin < end):
        temp = strlist[begin]
        strlist[begin] = strlist[end]
        strlist[end] = temp
        begin += 1
        end -= 1
    return ''.join(strlist)


class linux_kaslr_shift(linux_common.AbstractLinuxIntelCommand):
    """Automatically detect KASLR physical/virtual shifts and alternate DTBs"""

    def calculate(self):

        bitmask = 0xFFFFFFFFFF000
        page_marker = 0x8000000000000000

        # Monkeypatch address space check so we can continue
        linux_overlay.VolatilityLinuxIntelValidAS.generate_suggestions = \
            generate_suggestions_valid_as

        # Initalize address space, profile, etc.
        aspace = utils.load_as(self._config)
        linux_common.set_plugin_members(self)
        profile = self.profile
        tbl = profile.sys_map["kernel"]
        shift = profile.shift_address

        if profile.metadata.get('arch').lower() != 'x64':
            debug.error("This plugin only supports Intel x64 profiles")

        init_task_addr = tbl["init_task"][0][0]
        dtb_sym_addr = tbl["init_level4_pgt"][0][0]
        dtb_init_dist = init_task_addr - dtb_sym_addr

        # Monkeypatch amd64 address space
        aspace.get_nonzero_entries = get_nonzero_entries
        aspace.pdpte_index = pdpte_index

        # Retrieve the expected indices for the symbol for all 4
        # translation levels. These will be used to calculate the
        # difference between observed and expected indices in the
        # various tables
        pte_index = aspace.pte_index(init_task_addr)
        pde_index = aspace.pde_index(init_task_addr)
        pdpe_index = aspace.pdpte_index(aspace, init_task_addr)
        pml4e_index = aspace.pml4e_index(init_task_addr)

        expected = [pml4e_index, pdpe_index, pde_index, pte_index]

        # Determine all possible DTBs, the first one discovered might
        # not be the real one
        dtb_candidates = self.find_dtb_candidates(aspace,
                                                  dtb_init_dist,
                                                  init_task_addr)
        dtbs_and_offsets = {}
        for dtb, shift in dtb_candidates.iteritems():
            # Calculate the offset from DTB to init_task
            # init_task_phys is the physical address of the 'init_task' symbol
            # in the memory dump that is processed
            init_task_phys = dtb + dtb_init_dist
            debug.debug("Discovered DTB: {thisdtb:#x}".format(thisdtb = dtb))

            # Generate a nested dictionary of all pages
            tree = self.build_pte_tree(aspace, dtb)
            pte_to_search_for = hex(init_task_phys + page_marker)
            # Substitute last 3 bytes to '.', since their value may vary
            pte_to_search_for = \
                pte_to_search_for.replace(pte_to_search_for[-4:-1], '...')

            pte_regex = re.compile(pte_to_search_for)
            index_offsets = []

            searching = True
            while searching:
                pte_match = find_key(tree, pte_regex)
                if pte_match:
                    index_offsets.append(pte_match)
                    del tree[pte_match[0]][pte_match[1]][pte_match[2]][pte_match[3]]
                else:
                    # If nothing is found, abort the loop
                    searching = False

            dtbs_and_offsets[dtb] = index_offsets

        for dtb, index_offsets in dtbs_and_offsets.iteritems():
            candidates = []
            for pte_match in index_offsets:
                candidate = self.build_virtual_shift(expected, pte_match)
                if candidate:
                    candidate = int(candidate, 2)
                    yield [dtb, candidate, dtb_candidates[dtb] - candidate]

    def render_text(self, outfd, data):
        self.table_header(outfd, [("DTB", "[addrpad]"),
                                  ("Virtual Shift", "[addrpad]"),
                                  ("Physical Shift", "[addrpad]")])

        for shift_combination in data:
            self.table_row(outfd, shift_combination[0],
                           shift_combination[1], shift_combination[2])

    def format_index_binary(self, num):
        # For each level of address translation 9 bits are used to
        # determine the index in a map/table/directory

        # If the difference is negative the pte_match is not a
        # valid candidate, thus it will return False so that
        # the parent method can sort out invalid candidates
        if num < 0:
            return False
        else:
            return '{0:09b}'.format(num)

    def find_dtb_candidates(self, aspace, distance, init_task_addr):
        # Returns a dictionary of possible_dtb: shift combinations
        comm_offset = self.profile.get_obj_offset("task_struct", "comm")
        pid_offset = self.profile.get_obj_offset("task_struct", "pid")
        dtb_sym_addr = init_task_addr - distance
        shift = 0xffffffff80000000
        possible_dtbs = {}
        limespace = aspace.base

        scanner = linux_overlay.swapperScan(needles = ["swapper/0\x00\x00\x00\x00\x00\x00"])
        for swapper_offset in scanner.scan(aspace.base):
            swapper_address = swapper_offset - comm_offset

            if limespace.read(swapper_address, 4) != "\x00\x00\x00\x00":
                continue

            if limespace.read(swapper_address + pid_offset, 4) != "\x00\x00\x00\x00":
                continue

            tmp_shift_address = swapper_address - (init_task_addr - shift)

            if tmp_shift_address & 0xfff != 0x000:
                continue

            shift_address = tmp_shift_address
            good_dtb = dtb_sym_addr - shift + shift_address
            debug.debug("DTB: {thisdtb:#x}, Shift: {thisshift:#x}".format(thisdtb = good_dtb, thisshift = shift_address))

            possible_dtbs[good_dtb] = shift_address

        return possible_dtbs

    def build_virtual_shift(self, expected, real):
        # Bits [11:0] are the offset within the final page
        pageoffset = "000000000000"

        # For all indices in the 4 levels of tables,
        # calculate the difference between what is observed
        # and what is expected
        pt_diff = real[3] - expected[3]
        if pt_diff < 0:
            carry = 1
        else:
            carry = 0

        pd_diff = real[2] - expected[2] - carry
        if pd_diff < 0:
            carry = 1
        else:
            carry = 0

        pdptdiff = real[1] - expected[1] - carry
        if pd_diff < 0:
            carry = 1
        else:
            carry = 0

        pml4diff = real[0] - expected[0] - carry

        vshift = ''
        for diff in [pml4diff, pdptdiff, pd_diff, pt_diff]:
            vshift = vshift + self.format_index_binary(diff % 512)

        # This is the virtual shift due to KASLR encoded as bitstring
        vshift = vshift + pageoffset
        return vshift

    def build_pte_tree(self, aspace, dtb):
        """Builds a nested dictionary of all pages reachable from the DTB"""

        '''
        The nested dictionary will look like this:
       PML4 ind | PDPT Ind | PD Ind | PT Ind | PA of page
        {   279: {    91: {   0: {   0: '0x8000000000000163L',
                                     1: '0x8000000000001163L',
                                     ...
                                 },
                              2: {   15: ....
                                 }
                     123: ...
                 },
            511: { ...
                 }
        }
        '''
        tree = aspace.get_nonzero_entries(aspace, dtb)

        for pml4index, pdpt in tree.items():
            # Walk the pointertables
            pointertable = aspace.get_nonzero_entries(aspace, pdpt)

            # If the pointer table has no nonzero entries, it is
            # irrelevant for our key and we can delete the
            # pml4 entry (pdpt) from the tree
            if not pointertable:
                del tree[pml4index]
                continue

            # Walk the page directories
            for pdptindex, pd in pointertable.items():
                directory = aspace.get_nonzero_entries(aspace, pd)

                if not directory:
                    del pointertable[pdptindex]
                    continue

                # Walk the page tables
                for pdindex, pt in directory.items():
                    table = aspace.get_nonzero_entries(aspace, pt)
                    if not pt:
                        del directory[pdindex]
                        continue

                    for ind, tableentry in table.items():
                        try:
                            table[ind] = hex(tableentry)
                        except TypeError:
                            debug.debug("Miss: Could not convert entry {index:#d} in {pagetablebase:#x}".format(index = ind, pagetablebase = pt))

                    directory[pdindex] = table

                pointertable[pdptindex] = directory

            tree[pml4index] = pointertable
        return tree
