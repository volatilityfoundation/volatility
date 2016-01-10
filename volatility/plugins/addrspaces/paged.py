# Volatility
# Copyright (c) 2013 Volatility Foundation
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

#import fractions
import volatility.addrspace as addrspace
import volatility.obj as obj

class AbstractPagedMemory(addrspace.AbstractVirtualAddressSpace):
    """ Class to handle all the details of a paged virtual address space
        
    Note: Pages can be of any size
    """
    checkname = "Intel"

    def __init__(self, base, config, dtb = 0, skip_as_check = False, *args, **kwargs):
        ## We must be stacked on someone else:
        self.as_assert(base, "No base Address Space")

        addrspace.AbstractVirtualAddressSpace.__init__(self, base, config, *args, **kwargs)

        ## We can not stack on someone with a dtb
        self.as_assert(not (hasattr(base, 'paging_address_space') and base.paging_address_space), "Can not stack over another paging address space")

        self.dtb = dtb or self.load_dtb()
        # No need to set the base or dtb, it's already been by the inherited class

        self.as_assert(self.dtb != None, "No valid DTB found")

        if not skip_as_check:
            volmag = obj.VolMagic(self)
            if hasattr(volmag, self.checkname):
                self.as_assert(getattr(volmag, self.checkname).v(), "Failed valid Address Space check")
            else:
                self.as_assert(False, "Profile does not have valid Address Space check")

        # Reserved for future use
        #self.pagefile = config.PAGEFILE
        self.name = 'Kernel AS'

    def is_user_page(self, entry):
        """True if the page is accessible to ring 3 code"""
        raise NotImplementedError

    def is_supervisor_page(self, entry):
        """True if the page is /only/ accessible to ring 0 code"""
        raise NotImplementedError

    def is_writeable(self, entry):
        """True if the page can be written to"""
        raise NotImplementedError
        
    def is_dirty(self, entry):
        """True if the page has been written to"""
        raise NotImplementedError
        
    def is_nx(self, entry):
        """True if the page /cannot/ be executed"""
        raise NotImplementedError
        
    def is_accessed(self, entry):
        """True if the page has been accessed"""
        raise NotImplementedError
        
    def is_copyonwrite(self, entry):
        """True if the page is copy-on-write"""
        raise NotImplementedError

    def is_prototype(self, entry):
        """True if the page is a prototype PTE"""
        raise NotImplementedError

    def load_dtb(self):
        """Loads the DTB as quickly as possible from the config, then the base, then searching for it"""
        try:
            # If the user has manually specified one, then shortcircuit to that one
            if self._config.DTB:
                raise AttributeError

            ## Try to be lazy and see if someone else found dtb for
            ## us:
            return self.base.dtb
        except AttributeError:
            ## Ok so we need to find our dtb ourselves:
            dtb = obj.VolMagic(self.base).DTB.v()
            if dtb:
                ## Make sure to save dtb for other AS's
                ## Will this have an effect on following ASes attempts if this fails?
                self.base.dtb = dtb
                return dtb

    def __getstate__(self):
        result = addrspace.BaseAddressSpace.__getstate__(self)
        result['dtb'] = self.dtb

        return result

    @staticmethod
    def register_options(config):
        config.add_option("DTB", type = 'int', default = 0,
                          help = "DTB Address")

    def vtop(self, addr):
        """Abstract function that converts virtual (paged) addresses to physical addresses"""
        pass

    def get_available_pages(self):
        """A generator that returns (addr, size) for each of the virtual addresses present, sorted by offset"""
        pass

    def get_available_allocs(self):
        return self.get_available_pages()

    def get_available_addresses(self):
        """A generator that returns (addr, size) for each valid address block"""
        runLength = None
        currentOffset = None
        for (offset, size) in self.get_available_pages():
            if (runLength == None):
                runLength = size
                currentOffset = offset
            else:
                if (offset <= (currentOffset + runLength)):
                    runLength += (currentOffset + runLength - offset) + size
                else:
                    yield (currentOffset, runLength)
                    runLength = size
                    currentOffset = offset
        if (runLength != None and currentOffset != None):
            yield (currentOffset, runLength)
        raise StopIteration

    def is_valid_address(self, vaddr):
        """Returns whether a virtual address is valid"""
        if vaddr == None or vaddr < 0:
            return False
        try:
            paddr = self.vtop(vaddr)
        except BaseException:
            return False
        if paddr == None:
            return False
        return self.base.is_valid_address(paddr)

class AbstractWritablePagedMemory(AbstractPagedMemory):
    """
    Mixin class that can be used to add write functionality
    to any standard address space that supports write() and
    vtop().
    """
    def write(self, vaddr, buf):
        """Writes the data from buf to the vaddr specified
        
           Note: writes are not transactionaly, meaning if they can write half the data and then fail"""
        if not self._config.WRITE:
            return False

        if not self.alignment_gcd or not self.minimum_size:
            self.calculate_alloc_stats()

        position = vaddr
        length = len(buf)
        remaining = len(buf)

        # For each allocation...
        while remaining > 0:
            # Determine whether we're within an alloc or not
            alloc_remaining = (self.alignment_gcd - (vaddr % self.alignment_gcd))
            # Try to jump out early
            paddr = self.translate(position)
            datalen = min(remaining, alloc_remaining)
            if paddr is None:
                return False
            result = self.base.write(paddr, buf[:datalen])
            if not result:
                return False
            buf = buf[datalen:]
            position += datalen
            remaining -= datalen
            assert (vaddr + length == position + remaining), "Address + length != position + remaining (" + hex(vaddr + length) + " != " + hex(position + remaining) + ") in " + self.base.__class__.__name__
        return True
