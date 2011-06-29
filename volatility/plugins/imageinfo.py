# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import volatility.win32.tasks as tasks
import volatility.timefmt as timefmt
import volatility.utils as utils
import volatility.debug as debug
import volatility.obj as obj
import volatility.cache as cache
import volatility.registry as registry
import volatility.plugins.kdbgscan as kdbg

class ImageInfo(kdbg.KDBGScan):
    """ Identify information for the image """
    def __init__(self, config, args = None):
        kdbg.KDBGScan.__init__(self, config, args)

    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        for k, v in data:
            outfd.write("{0:>30} : {1}\n".format(k, v))

    @cache.CacheDecorator("tests/imageinfo")
    def calculate(self):
        """Calculates various information about the image"""
        print "Determining profile based on KDBG search...\n"
        profilelist = [ p.__name__ for p in registry.PROFILES.classes ]

        bestguess = None
        suglist = [ s for s, _, _ in kdbg.KDBGScan.calculate(self)]
        if suglist:
            bestguess = suglist[0]
        suggestion = ", ".join(suglist)

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

        yield ('Suggested Profile(s)', suggestion)

        tmpas = addr_space
        count = 0
        while tmpas:
            count += 1
            yield ('AS Layer' + str(count), tmpas.__class__.__name__ + " (" + tmpas.name + ")")
            tmpas = tmpas.base

        if not hasattr(addr_space, "pae"):
            yield ('PAE type', "No PAE")
        else:
            yield ('PAE type', "PAE" if addr_space.pae else "No PAE")

        if hasattr(addr_space, "dtb"):
            yield ('DTB', hex(addr_space.dtb))

        volmagic = obj.Object('VOLATILITY_MAGIC', 0x0, addr_space)
        kpcroffset = None
        if hasattr(addr_space, "dtb"):
            kdbgoffset = volmagic.KDBG.v()
            if kdbgoffset:
                yield ('KDBG', hex(kdbgoffset))

            kpcroffset = volmagic.KPCR.v()
            if kpcroffset:
                yield ('KPCR', hex(kpcroffset))
                KUSER_SHARED_DATA = volmagic.KUSER_SHARED_DATA.v()
                if KUSER_SHARED_DATA:
                    yield ('KUSER_SHARED_DATA', hex(KUSER_SHARED_DATA))

                data = self.get_image_time(addr_space)

                if data:
                    yield ('Image date and time', data['ImageDatetime'])
                    yield ('Image local date and time', timefmt.display_datetime(data['ImageDatetime'].as_datetime(), data['ImageTz']))

                for csdversion, numprocessors in self.find_task_items(addr_space):
                    try:
                        yield ('Number of Processors', numprocessors)
                        yield ('Image Type', csdversion)
                    except tasks.TasksNotFound:
                        pass

        # Make sure to reset the profile to its original value to keep the invalidator from blocking the cache
        self._config.update('PROFILE', origprofile)

    def get_image_time(self, addr_space):
        """Get the Image Datetime"""
        result = {}
        volmagic = obj.Object("VOLATILITY_MAGIC", 0x0, addr_space)
        KUSER_SHARED_DATA = volmagic.KUSER_SHARED_DATA.v()
        k = obj.Object("_KUSER_SHARED_DATA",
                              offset = KUSER_SHARED_DATA,
                              vm = addr_space)

        if k == None:
            return k
        result['ImageDatetime'] = k.SystemTime
        result['ImageTz'] = timefmt.OffsetTzInfo(-k.TimeZoneBias.as_windows_timestamp() / 10000000)

        return result

    #I don't know what's better, but I don't think we need to go through all tasks twice
    #so I combined finding csdvers and MaxNumberOfProcessors into one
    def find_task_items(self, addr_space):
        """Find items that require task list traversal"""
        csdvers = {}
        procnumdict = {}

        procnumresult = obj.NoneObject("Unable to find number of processors")
        cdsresult = obj.NoneObject("Unable to find version")

        for task in tasks.pslist(addr_space):
            if task.Peb.CSDVersion != None:
                csdvers[str(task.Peb.CSDVersion)] = csdvers.get(str(task.Peb.CSDVersion), 0) + 1

            if task.Peb.NumberOfProcessors != None:
                procnumdict[int(task.Peb.NumberOfProcessors)] = procnumdict.get(int(task.Peb.NumberOfProcessors), 0) + 1

        #I don't know if you can actually get the number of CPUs w/o CSDVersion, but just in case...
        if csdvers:
            _, _, cdsresult = max([(v, k, str(k)) for k, v in csdvers.items()])
        if procnumdict:
            _, procnumresult = max([(v, k) for k, v in procnumdict.items()])

        yield (cdsresult, procnumresult)

