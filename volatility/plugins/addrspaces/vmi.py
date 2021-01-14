# Volatility
#
# Copyright 2011 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
# retains certain rights in this software.
#
# Authors:
# bdpayne@acm.org (Bryan D. Payne)
# mathieu.tarral@protonmail.com (Mathieu Tarral)
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
from urlparse import urlparse
from distutils.util import strtobool
import volatility.addrspace as addrspace

libvmi = None
try:
    import libvmi
    from libvmi import Libvmi, VMIMode, CR3
except ImportError:
    pass

SCHEME = 'vmi'


class VMIAddressSpace(addrspace.BaseAddressSpace):
    """
    This address space can be used in conjunction with LibVMI
    and the Python bindings for LibVMI.  The end result is that
    you can connect Volatility to view the memory of a running
    virtual machine from any virtualization platform that
    LibVMI supports.

    For this AS to be instantiated, we need the VM name to
    connect to.
    """

    order = 90

    def __init__(self, base, config, layered=False, **kwargs):
        self.as_assert(libvmi, "The LibVMI python bindings must be installed")
        self.as_assert(base is None or layered, 'Must be first Address Space')

        url = config.LOCATION
        vmi_url = urlparse(url)
        self.as_assert(vmi_url.scheme == SCHEME,
                       "URL scheme must be {}://".format(SCHEME))
        self.as_assert(vmi_url.path, "No domain name specified")
        domain = vmi_url.path[1:]
        # hypervisor specified ?
        self.mode = None
        hypervisor = vmi_url.netloc
        if hypervisor:
            self.mode = VMIMode[hypervisor.upper()]
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        # build Libvmi instance
        self.vmi = Libvmi(domain, mode=self.mode, partial=True)
        self.min_addr = 0
        self.max_addr = self.vmi.get_memsize()
        self.dtb = self.vmi.get_vcpu_reg(CR3, 0)

    def close(self):
        self.vmi.destroy()

    def read(self, addr, length):
        buffer, bytes_read = self.vmi.read_pa(addr, length)
        if bytes_read != length:
            raise RuntimeError('Error while reading physical memory at '
                               '{}'.format(hex(addr)))
        return buffer

    def zread(self, addr, length):
        return self.vmi.read_pa_padded(addr, length)

    def write(self, addr, data):
        bytes_written = self.vmi.write_pa(addr, data)
        if bytes_written != len(data):
            return False
        return True

    def is_valid_address(self, addr):
        if addr is None:
            return False
        return self.min_addr < addr < self.max_addr

    def get_available_addresses(self):
        yield (self.min_addr, self.max_addr)
