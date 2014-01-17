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

import volatility.obj as obj
import volatility.scan as scan
import volatility.cache as cache
import volatility.plugins.common as common
import volatility.addrspace as addrspace
import volatility.registry as registry
import volatility.utils as utils
import volatility.exceptions as exceptions

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
            if buf.profile.metadata.get('os', 'unknown') == 'windows':
                proflens[p] = str(obj.VolMagic(buf).KDBGHeader)
                maxlen = max(maxlen, len(proflens[p]))
        self._config.update('PROFILE', origprofile)

        scanner = KDBGScanner(needles = proflens.values())

        aspace = utils.load_as(self._config, astype = 'any')

        for offset in scanner.scan(aspace):
            val = aspace.read(offset, maxlen + 0x10)
            for l in proflens:
                if val.find(proflens[l]) >= 0:
                    kdbg = obj.Object("_KDDEBUGGER_DATA64", offset = offset, vm = aspace)
                    yield l, kdbg

    def render_text(self, outfd, data):
        """Renders the KPCR values as text"""

        for profile, kdbg in data:

            outfd.write("*" * 50 + "\n")
            outfd.write("Instantiating KDBG using: {0} {1} ({2}.{3}.{4} {5})\n".format(
                        kdbg.obj_vm.name, kdbg.obj_vm.profile.__class__.__name__,
                        kdbg.obj_vm.profile.metadata.get('major', 0),
                        kdbg.obj_vm.profile.metadata.get('minor', 0),
                        kdbg.obj_vm.profile.metadata.get('build', 0),
                        kdbg.obj_vm.profile.metadata.get('memory_model', '32bit'),
                        ))

            # Will spaces with vtop always have a dtb also? 
            has_vtop = hasattr(kdbg.obj_vm, 'vtop')

            # Always start out with the virtual and physical offsets
            if has_vtop:
                outfd.write("{0:<30}: {1:#x}\n".format("Offset (V)", kdbg.obj_offset))
                outfd.write("{0:<30}: {1:#x}\n".format("Offset (P)", kdbg.obj_vm.vtop(kdbg.obj_offset)))
            else:
                outfd.write("{0:<30}: {1:#x}\n".format("Offset (P)", kdbg.obj_offset))

            # These fields can be gathered without dereferencing
            # any pointers, thus they're available always 
            outfd.write("{0:<30}: {1}\n".format("KDBG owner tag check", str(kdbg.is_valid())))
            outfd.write("{0:<30}: {1}\n".format("Profile suggestion (KDBGHeader)", profile))
            verinfo = kdbg.dbgkd_version64()
            if verinfo:
                outfd.write("{0:<30}: {1:#x} (Major: {2}, Minor: {3})\n".format(
                    "Version64", verinfo.obj_offset, verinfo.MajorVersion,
                    verinfo.MinorVersion))

            # Print details only available when a DTB can be found
            # and we have an AS with vtop. 
            if has_vtop:
                outfd.write("{0:<30}: {1}\n".format("Service Pack (CmNtCSDVersion)", kdbg.ServicePack))
                outfd.write("{0:<30}: {1}\n".format("Build string (NtBuildLab)", kdbg.NtBuildLab.dereference()))

                try:
                    num_tasks = len(list(kdbg.processes()))
                except AttributeError:
                    num_tasks = 0
                try:
                    num_modules = len(list(kdbg.modules()))
                except AttributeError:
                    num_modules = 0

                cpu_blocks = list(kdbg.kpcrs())

                outfd.write("{0:<30}: {1:#x} ({2} processes)\n".format(
                    "PsActiveProcessHead", kdbg.PsActiveProcessHead, num_tasks))

                outfd.write("{0:<30}: {1:#x} ({2} modules)\n".format(
                    "PsLoadedModuleList", kdbg.PsLoadedModuleList, num_modules))

                outfd.write("{0:<30}: {1:#x} (Matches MZ: {2})\n".format(
                    "KernelBase", kdbg.KernBase, str(kdbg.obj_vm.read(kdbg.KernBase, 2) == "MZ")))

                try:
                    dos_header = obj.Object("_IMAGE_DOS_HEADER",
                                    offset = kdbg.KernBase,
                                    vm = kdbg.obj_vm)
                    nt_header = dos_header.get_nt_header()
                except (ValueError, exceptions.SanityCheckException):
                    pass
                else:
                    outfd.write("{0:<30}: {1}\n".format(
                        "Major (OptionalHeader)",
                        nt_header.OptionalHeader.MajorOperatingSystemVersion))
                    outfd.write("{0:<30}: {1}\n".format(
                        "Minor (OptionalHeader)",
                        nt_header.OptionalHeader.MinorOperatingSystemVersion))

                for kpcr in cpu_blocks:
                    outfd.write("{0:<30}: {1:#x} (CPU {2})\n".format(
                        "KPCR", kpcr.obj_offset, kpcr.ProcessorBlock.Number))
            else:
                outfd.write("{0:<30}: {1:#x}\n".format("PsActiveProcessHead", kdbg.PsActiveProcessHead))
                outfd.write("{0:<30}: {1:#x}\n".format("PsLoadedModuleList", kdbg.PsLoadedModuleList))
                outfd.write("{0:<30}: {1:#x}\n".format("KernelBase", kdbg.KernBase))

            outfd.write("\n")

