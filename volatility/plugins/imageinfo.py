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

import volatility.win32.tasks as tasks
import volatility.timefmt as timefmt
import volatility.utils as utils
import volatility.debug as debug
import volatility.obj as obj
import volatility.cache as cache
import volatility.registry as registry
import volatility.plugins.kdbgscan as kdbgscan
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class ImageInfo(kdbgscan.KDBGScan):
    """ Identify information for the image """
    def unified_output(self, data):
        columns = []
        values = []
        for l, t, v in data:
          columns.append( (l, t) )
          values.append(v)
        return TreeGrid(columns, [(0, values)])

    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        for k, t, v in data:
            outfd.write("{0:>30} : {1}\n".format(k, hex(v) if t is Address else v))

    @cache.CacheDecorator("tests/imageinfo")
    def calculate(self):
        """Calculates various information about the image"""
        debug.info("Determining profile based on KDBG search...")
        profilelist = [ p.__name__ for p in registry.get_plugin_classes(obj.Profile).values() ]

        bestguess = None
        suglist = [ s for s, _ in kdbgscan.KDBGScan.calculate(self)]
        if suglist:
            bestguess = suglist[0]
        suggestion = ", ".join(set(suglist))

        # Set our suggested profile first, then run through the list
        if bestguess in profilelist:
            profilelist = [bestguess] + profilelist
        chosen = 'no profile'

        # Save the original profile
        origprofile = self._config.PROFILE
        # Force user provided profile over others
        profilelist = [origprofile] + profilelist

        for profile in profilelist:
            debug.debug('Trying profile ' + profile)
            self._config.update('PROFILE', profile)
            addr_space = utils.load_as(self._config, astype = 'any')
            if hasattr(addr_space, "dtb"):
                chosen = profile
                break

        if bestguess != chosen:
            if not suggestion:
                suggestion = 'No suggestion'
            suggestion += ' (Instantiated with ' + chosen + ')'

        yield ('Suggested Profile(s)', str, suggestion)

        tmpas = addr_space
        count = 0
        while tmpas:
            count += 1
            yield ('AS Layer' + str(count), str,
                   tmpas.__class__.__name__ + " (" + tmpas.name + ")")
            tmpas = tmpas.base

        if not hasattr(addr_space, "pae"):
            yield ('PAE type', str, "No PAE")
        else:
            yield ('PAE type', str, "PAE" if addr_space.pae else "No PAE")

        if hasattr(addr_space, "dtb"):
            yield ('DTB', Address, Address(addr_space.dtb))

        volmagic = obj.VolMagic(addr_space)
        if hasattr(addr_space, "dtb") and hasattr(volmagic, "KDBG"):
            kdbg = volmagic.KDBG.v()
            if type(kdbg) == int:
                kdbg = obj.Object("_KDDEBUGGER_DATA64", offset = kdbg, vm = addr_space)
            if kdbg.is_valid():
                yield ('KDBG', Address, Address(kdbg.obj_offset))
                kpcr_list = list(kdbg.kpcrs())
                yield ('Number of Processors', int, len(kpcr_list))
                yield ('Image Type (Service Pack)', int, kdbg.ServicePack)
                for kpcr in kpcr_list:
                    yield ('KPCR for CPU {0}'.format(kpcr.ProcessorBlock.Number),
                        Address, Address(kpcr.obj_offset))

            KUSER_SHARED_DATA = volmagic.KUSER_SHARED_DATA.v()
            if KUSER_SHARED_DATA:
                yield ('KUSER_SHARED_DATA', Address, Address(KUSER_SHARED_DATA))

            data = self.get_image_time(addr_space)

            if data:
                yield ('Image date and time', str, str(data['ImageDatetime']))
                yield ('Image local date and time', str,
                       timefmt.display_datetime(data['ImageDatetime'].as_datetime(), data['ImageTz']))

        # Make sure to reset the profile to its original value to keep the invalidator from blocking the cache
        self._config.update('PROFILE', origprofile)

    def get_image_time(self, addr_space):
        """Get the Image Datetime"""
        result = {}
        KUSER_SHARED_DATA = obj.VolMagic(addr_space).KUSER_SHARED_DATA.v()
        k = obj.Object("_KUSER_SHARED_DATA",
                       offset = KUSER_SHARED_DATA,
                       vm = addr_space)

        if k == None:
            return k
        result['ImageDatetime'] = k.SystemTime
        result['ImageTz'] = timefmt.OffsetTzInfo(-k.TimeZoneBias.as_windows_timestamp() / 10000000)

        return result
