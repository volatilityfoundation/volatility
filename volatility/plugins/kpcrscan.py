# Volatility
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

"""
@author:       Bradley Schatz 
@license:      GNU General Public License 2.0
@contact:      bradley@schatzforensic.com.au
@organization: Schatz Forensic
"""

import struct
import volatility.utils as utils
import volatility.scan as scan
import volatility.cache as cache
import volatility.plugins.common as common
import volatility.obj as obj
import volatility.plugins.addrspaces.intel as intel
import volatility.plugins.addrspaces.amd64 as amd64

class KPCRScan(common.AbstractWindowsCommand):
    """Search for and dump potential KPCR values"""

    meta_info = dict(
        author = 'Bradley Schatz',
        copyright = 'Copyright (c) 2010 Bradley Schatz',
        contact = 'bradley@schatzforensic.com.au',
        license = 'GNU General Public License 2.0',
        url = 'http://www.schatzforensic.com.au/',
        os = 'WIN_32_VISTA_SP0',
        version = '1.0',
        )

    @staticmethod
    def register_options(config):
        config.add_option('KPCR', short_option = 'k', default = None, type = 'int',
                          help = "Specify a specific KPCR address")

    @cache.CacheDecorator("tests/kpcrscan")
    def calculate(self):
        """Determines the address space"""
        addr_space = utils.load_as(self._config, astype = 'any')

        scanner = KPCRScanner()
        for offset in scanner.scan(addr_space):
            kpcr = obj.Object("_KPCR", offset = offset, vm = addr_space)
            yield kpcr

    def render_text(self, outfd, data):
        """Renders the KPCR values as text"""

        for kpcr in data:
            outfd.write("*" * 50 + "\n")

            if hasattr(kpcr.obj_vm, 'vtop'):
                outfd.write("{0:<30}: {1:#x}\n".format("Offset (V)", kpcr.obj_offset))
                outfd.write("{0:<30}: {1:#x}\n".format("Offset (P)", kpcr.obj_vm.vtop(kpcr.obj_offset)))
            else:
                outfd.write("{0:<30}: {1:#x}\n".format("Offset (P)", kpcr.obj_offset))

            outfd.write("{0:<30}: {1:#x}\n".format("KdVersionBlock", kpcr.KdVersionBlock))
            outfd.write("{0:<30}: {1:#x}\n".format("IDT", kpcr.IDT))
            outfd.write("{0:<30}: {1:#x}\n".format("GDT", kpcr.GDT))

            current_thread = kpcr.ProcessorBlock.CurrentThread.dereference_as("_ETHREAD")
            idle_thread = kpcr.ProcessorBlock.IdleThread.dereference_as("_ETHREAD")
            next_thread = kpcr.ProcessorBlock.NextThread.dereference_as("_ETHREAD")

            if current_thread:
                outfd.write("{0:<30}: {1:#x} TID {2} ({3}:{4})\n".format(
                    "CurrentThread", 
                    current_thread.obj_offset, current_thread.Cid.UniqueThread, 
                    current_thread.owning_process().ImageFileName, 
                    current_thread.Cid.UniqueProcess, 
                    ))

            if idle_thread:
                outfd.write("{0:<30}: {1:#x} TID {2} ({3}:{4})\n".format(
                    "IdleThread", 
                    idle_thread.obj_offset, idle_thread.Cid.UniqueThread, 
                    idle_thread.owning_process().ImageFileName, 
                    idle_thread.Cid.UniqueProcess, 
                    ))

            if next_thread:
                outfd.write("{0:<30}: {1:#x} TID {2} ({3}:{4})\n".format(
                    "NextThread", 
                    next_thread.obj_offset, 
                    next_thread.Cid.UniqueThread, 
                    next_thread.owning_process().ImageFileName, 
                    next_thread.Cid.UniqueProcess, 
                    ))

            outfd.write("{0:<30}: CPU {1} ({2} @ {3} MHz)\n".format("Details", 
                kpcr.ProcessorBlock.Number, 
                kpcr.ProcessorBlock.VendorString,
                kpcr.ProcessorBlock.MHz))

            outfd.write("{0:<30}: {1:#x}\n".format("CR3/DTB", 
                kpcr.ProcessorBlock.ProcessorState.SpecialRegisters.Cr3))            

class KPCRScannerCheck(scan.ScannerCheck):
    """Checks the self referential pointers to find KPCRs"""
    def __init__(self, address_space):
        scan.ScannerCheck.__init__(self, address_space)
        kpcr = obj.Object("_KPCR", vm = self.address_space, offset = 0)
        if address_space.profile.metadata.get('memory_model', '') == '32bit':
            self.SelfPcr_offset = kpcr.SelfPcr.obj_offset
            self.Prcb_offset = kpcr.Prcb.obj_offset
            self.PrcbData_offset = kpcr.PrcbData.obj_offset
            # In the check() routine, we need to compare masked virtual 
            # addresses, but self.address_space is a BufferAddressSpace. 
            self.address_equality = amd64.AMD64PagedMemory.address_equality
        else:
            # The self-referencing member of _KPCR is Self on x64
            self.SelfPcr_offset = kpcr.Self.obj_offset
            # The pointer to _KPRCB is CurrentPrcb on x64
            self.Prcb_offset = kpcr.CurrentPrcb.obj_offset
            # The nested _KPRCB in Prcb on x64
            self.PrcbData_offset = kpcr.Prcb.obj_offset
            self.address_equality = intel.IA32PagedMemory.address_equality
        self.KPCR = None

    def check(self, offset):
        """ We check that _KCPR.pSelfPCR points to the start of the _KCPR struct """
        paKCPR = offset
        paPRCBDATA = offset + self.PrcbData_offset

        try:
            pSelfPCR = obj.Object('Pointer', offset = (offset + self.SelfPcr_offset), vm = self.address_space)
            pPrcb = obj.Object('Pointer', offset = (offset + self.Prcb_offset), vm = self.address_space)
            if self.address_equality(pSelfPCR, paKCPR) and self.address_equality(pPrcb, paPRCBDATA):
                self.KPCR = pSelfPCR
                return True

        except BaseException:
            return False

        return False

    # make the scan DWORD aligned
    def skip(self, data, offset):
        return 4

        offset_string = struct.pack("I", offset)

        new_offset = offset
        ## A successful match will need to at least match the Most
        ## Significant 3 bytes
        while (new_offset + self.SelfPcr_offset) & 0xFF >= self.SelfPcr_offset:
            new_offset = data.find(offset_string[3], new_offset + 1)
            ## Its not there, skip the whole buffer
            if new_offset < 0:
                return len(data) - offset

            if (new_offset % 4) == 0:
                return new_offset - self.SelfPcr_offset - 1

        return len(data) - offset

class KPCRScanner(scan.BaseScanner):
    checks = [ ("KPCRScannerCheck", {})
               ]
    def scan(self, address_space, offset = 0, maxlen = None):
        return scan.BaseScanner.scan(self, address_space, max(offset, 0x80000000), maxlen)
