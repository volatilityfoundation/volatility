# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

""" This plugin contains CORE classes used by lots of other plugins """
import volatility.poolscan as poolscan
import volatility.utils as utils
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.commands as commands

#pylint: disable-msg=C0111

class AbstractWindowsCommand(commands.Command):
    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'unknown') == 'windows'

class AbstractScanCommand(AbstractWindowsCommand):
    """A command built to provide the common options that
    should be available to Volatility's various scanning 
    plugins."""    

    # This is a list of scanners to use 
    scanners = []

    def __init__(self, config, *args, **kwargs):
        AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("VIRTUAL", short_option = "V", default = False,
                          action = "store_true", 
                          help = "Scan virtual space instead of physical")
        config.add_option("SHOW-UNALLOCATED", short_option = "W", default = False,
                          action = "store_true", 
                          help = "Skip unallocated objects (e.g. 0xbad0b0b0)")
        config.add_option("START", short_option = "A", default = None, 
                          action = "store", type = "int", 
                          help = "The starting address to begin scanning")
        config.add_option("LENGTH", short_option = "G", default = None, 
                          action = "store", type = "int", 
                          help = "Length (in bytes) to scan from the starting address")

    def calculate(self):
        addr_space = utils.load_as(self._config)
        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")
        return self.scan_results(addr_space)

    def offset_column(self):
        return "Offset(V)" if self._config.VIRTUAL else "Offset(P)"

    def scan_results(self, addr_space):
        use_top_down = (addr_space.profile.metadata.get("major", 0) == 6 
                        and addr_space.profile.metadata.get("minor") >= 2)

        multiscan = poolscan.MultiScanInterface(addr_space = addr_space, 
                                scanners = self.scanners,
                                scan_virtual = self._config.VIRTUAL, 
                                show_unalloc = self._config.SHOW_UNALLOCATED,
                                use_top_down = use_top_down,
                                start_offset = self._config.START, 
                                max_length = self._config.LENGTH)

        return multiscan.scan()

def pool_align(vm, object_name, align):
    """Returns the size of the object accounting for pool alignment."""
    size_of_obj = vm.profile.get_obj_size(object_name)

    # Size is rounded to pool alignment
    extra = size_of_obj % align
    if extra:
        size_of_obj += align - extra

    return size_of_obj