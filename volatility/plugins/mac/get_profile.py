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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.registry as registry
import volatility.plugins.mac.common as common

profiles = [
["MacYosemite_10_10_14A389x64", 18446743523963612480, 18446743523964534784, 1],
["MacYosemite_10_10_14B25x64", 18446743523963612480, 18446743523964534784, 1],
["MacYosemite_10_10_2_14C1514x64", 18446743523963607600, 18446743523964534784, 1],
["MacYosemite_10_10_3_14D131x64", 18446743523963609408, 18446743523964534784, 1],
["MacYosemite_10_10_3_14D136x64", 18446743523963609408, 18446743523964534784, 1],
["MacYosemite_10_10_4_14E46x64", 18446743523963610496, 18446743523964534784, 1],
["MacYosemite_10_10_5_14F27x64", 18446743523963608608, 18446743523964534784, 1],
["MacYosemite_10_10_5_14F1021x64", 18446743523963608704, 18446743523964534784, 1],
["MacLeopard_10_5_3_Intelx86", 4850472, 1708032, 0],
["MacLeopard_10_5_4_Intelx86", 4850488, 1708032, 0],
["MacLeopard_10_5_5_Intelx86", 4850568, 1708032, 0],
["MacLeopard_10_5_6_Intelx86", 4859540, 1712128, 0],
["MacLeopard_10_5_7_Intelx86", 4880064, 1716224, 0],
["MacLeopard_10_5_8_Intelx86", 4882736, 1716224, 0],
["MacLeopard_10_5_Intelx86", 4823024, 1703936, 0],
["MacSnowLeopard_10_6_1_AMDx64", 18446743523959762264, 18446743523956649984, 0],
["MacSnowLeopard_10_6_2_AMDx64", 18446743523959767128, 18446743523956654080, 0],
["MacSnowLeopard_10_6_4_AMDx64", 18446743523959767504, 18446743523956662272, 0],
["MacSnowLeopard_10_6_5_AMDx64", 18446743523959780720, 18446743523956666368, 0],
["MacSnowLeopard_10_6_6_AMDx64", 18446743523959780936, 18446743523956666368, 0],
["MacSnowLeopard_10_6_7_AMDx64", 18446743523959800160, 18446743523956666368, 0],
["MacSnowLeopard_10_6_8_AMDx64", 18446743523959819016, 18446743523956670464, 0],
["MacSnowLeopard_10_6_AMDx64", 18446743523959762264, 18446743523956649984, 0],
["MacSnowLeopard_10_6_1_Intelx86", 6139972, 2744320, 0],
["MacSnowLeopard_10_6_2_Intelx86", 6144688, 2748416, 0],
["MacSnowLeopard_10_6_3_Intelx86", 6139684, 2752512, 0],
["MacSnowLeopard_10_6_4_Intelx86", 6143412, 2752512, 0],
["MacSnowLeopard_10_6_5_Intelx86", 6165360, 2760704, 0],
["MacSnowLeopard_10_6_6_Intelx86", 6165676, 2760704, 0],
["MacSnowLeopard_10_6_7_Intelx86", 6186376, 2760704, 0],
["MacSnowLeopard_10_6_8_Intelx86", 6203832, 2764800, 0],
["MacSnowLeopard_10_6_Intelx86", 6139972, 2744320, 0],
["MacLion_10_7_1_AMDx64", 18446743523961030696, 18446743523956600832, 0],
["MacLion_10_7_2_AMDx64", 18446743523961030368, 18446743523956600832, 0],
["MacLion_10_7_3_AMDx64", 18446743523961032256, 18446743523956600832, 0],
["MacLion_10_7_4_AMDx64", 18446743523961048360, 18446743523956609024, 0],
["MacLion_10_7_5_AMDx64", 18446743523961053360, 18446743523956609024, 0],
["MacLion_10_7_AMDx64", 18446743523961030304, 18446743523956600832, 0],
["MacLion_10_7_1_Intelx86", 7447336, 2899968, 0],
["MacLion_10_7_2_Intelx86", 7451396, 2904064, 0],
["MacLion_10_7_3_Intelx86", 7453552, 2904064, 0],
["MacLion_10_7_4_Intelx86", 7464424, 2908160, 0],
["MacLion_10_7_5_Intelx86", 7468772, 2908160, 0],
["MacLion_10_7_Intelx86", 7446904, 2899968, 0],
["MacMountainLion_10_8_1_AMDx64", 18446743523961328192, 18446743523962269696, 1],
["MacMountainLion_10_8_2_AMDx64", 18446743523961340528, 18446743523962269696, 1],
["MacMountainLion_10_8_3_AMDx64", 18446743523961294000, 18446743523962269696, 1],
["MacMountainLion_10_8_4_12e55_AMDx64", 18446743523961302256, 18446743523962269696, 1],
["MacMountainLion_10_8_5_12f37_AMDx64", 18446743523961347136, 18446743523962273792, 1],
["MacMountainLion_10_8_5_12f45_AMDx64", 18446743523961347136, 18446743523962273792, 1],
["MacMavericks_10_9_1_AMDx64", 18446743523961749984, 18446743523962273792, 1],
["MacMavericks_10_9_2_13C1021_AMDx64", 18446743523961751392, 18446743523962273792, 1],
["MacMavericks_10_9_2__13C64_AMDx64", 18446743523961753424, 18446743523962273792, 1],
["MacMavericks_10_9_3_AMDx64", 18446743523961765744, 18446743523962273792, 1],
["MacMavericks_10_9_4_AMDx64", 18446743523961767008, 18446743523962273792, 1],
["MacMavericks_10_9_5_AMDx64", 18446743523961765968, 18446743523962273792, 1],
["MacElCapitan_10_11_15A284x64", 18446743523963516960, 18446743523964547072, 1],
["MacElCapitan_10_11_1_15B42x64", 18446743523963517744, 18446743523964555264, 1],
["MacElCapitan_10_11_2_15C50x64", 18446743523963517440, 18446743523964555264, 1],
["MacElCapitan_10_11_3_15D13bx64", 18446743523963520864, 18446743523964555264, 1],
["MacElCapitan_10_11_3_15D21x64", 18446743523963520864, 18446743523964555264, 1],
["MacElCapitan_10_11_4_15E65x64", 18446743523963511520, 18446743523964555264, 1],
]

class catfishScan(scan.BaseScanner):
    """ Scanner for Catfish string for Mountain Lion """
    checks = []

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles}) ]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

# based on kdbgscan
class mac_get_profile(common.AbstractMacCommand):
    """Automatically detect Mac profiles"""

    @staticmethod
    def check_address(ver_addr, aspace):
        if ver_addr > 0xffffffff:
            ver_addr = ver_addr - 0xffffff8000000000
        elif ver_addr > 0xc0000000:
            ver_addr = ver_addr - 0xc0000000

        ver_buf = aspace.read(ver_addr, 32)
        sig = "Darwin Kernel"
        return ver_buf and ver_buf.startswith(sig)

    @staticmethod
    def guess_profile(aspace):
        """Main interface to guessing Mac profiles. 
        
        Args: 
            aspace: a physical address space.
            
        Returns:
            Tuple containing the profile name and 
            shift address. 
            
            On failure, it implicitly returns None.
        """
        
        for data in profiles:
            if mac_get_profile.check_address(data[1], aspace):
                return data[0], 0 
            
        # didn't find a direct translation, so look for KASLR kernels
        scanner = catfishScan(needles = ["Catfish \x00\x00"])
        for catfish_offset in scanner.scan(aspace):
            for profile, ver_addr, lowglo, aslr in profiles:
                if not aslr or not lowglo:
                    continue

                shift_address = (catfish_offset -\
                     (lowglo % 0xFFFFFF80))

                ver_addr += shift_address
                
                if mac_get_profile.check_address(ver_addr, aspace):
                    return profile, shift_address

    def calculate(self):
        aspace = utils.load_as(self._config, astype = 'physical')
        
        result = mac_get_profile.guess_profile(aspace)

        if result:
            yield result
        else:
            debug.error("Unable to find an OS X profile for the given memory sample.")
                    
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Profile", "50"), ("Shift Address", "[addrpad]")])

        for profile, shift_address in data:
            self.table_row(outfd, profile, shift_address)
