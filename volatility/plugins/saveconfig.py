# Volatility
#
# Author:
# Andrew Cook <cooka2011@gmail.com>
#
# This file is part of Volatility./
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

import volatility.plugins.common as common
import volatility.conf as conf
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.kdbgscan as kdbgscan
import volatility.obj as obj
import volatility.cache as cache
import volatility.registry as registry
import ConfigParser

class SaveConfig(kdbgscan.KDBGScan): # common.AbstractWindowsCommand):
    """Generates Volatility configuration files"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option("DEST", default = "./volatilityrc", short_option = "D",
            help = "File to save the generated configuration")

        config.add_option("EXCLUDE-CONF", default = False, short_option = "E",
            action = "store_true", help = "Do not read options from configuration files")

        config.add_option("MODIFY", default = False, short_option = "M",
            action = "store_true", help = "Modify (rather than override) the generated configuration file")

        config.add_option("OFFSETS", default = False,
            action = "store_true", help = "Get offsets, like KDBG and DTB")

        config.add_option("AUTO", default = False,
            action = "store_true", help = "Attempt to automatically determine profile")

        ## Used to make sure we do not save our own options and options that are already saved
        self._exclude_options = ["dest", "exclude_conf", "modify", "offsets", "auto"]

    def calculate(self):
        self.new_config = ConfigParser.RawConfigParser()
        self.save_location = self._config.DEST

        ## Read from existing target configuration (if modifying)
        if self._config.MODIFY:
            self.new_config.read(self.save_location)

        ## Attempt to automatically determine profile
        if self._config.AUTO:
            print("Determining profile based on KDBG search...")
            self.suglist = [ s for s, _ in kdbgscan.KDBGScan.calculate(self)]
            if self.suglist:
                self.new_config.set("DEFAULT", "profile", self.suglist[0])
                ## Update profile so --offsets will work
                self._config.PROFILE = self.suglist[0]
                self._exclude_options.append('profile')
            else:
                print("Failed to determine profile")

        ## Read in current command line (precedence over settings in configs)
        for key in self._config.opts:
            if key not in self._exclude_options:
                self.new_config.set("DEFAULT", key, self._config.opts[key])
                ## Add to excluded list so we do not overwrite them later
                self._exclude_options.append(key)

        ## Save options from configuration files (unless excluded by user)
        if self._config.EXCLUDE_CONF == False:
            for key in self._config.cnf_opts:
                if key not in self._exclude_options:
                    self.new_config.set("DEFAULT", key, self._config.cnf_opts[key])

        if self._config.OFFSETS:
            addr_space = utils.load_as(self._config)
            kdbg = tasks.get_kdbg(addr_space)
            self.new_config.set("DEFAULT", "kdbg", str(hex(kdbg.v())))
            if hasattr(addr_space, "dtb"):
                self.new_config.set("DEFAULT", "dtb", str(hex(addr_space.dtb)))



        ## Write the actual configuration file
        with open(self.save_location, "wb") as configfile:
            self.new_config.write(configfile)

    def max_width(self):
        """ Return length of the longest key and longest value """
        max_key_width = 0
        max_val_width = 0

        for key, val in self.new_config.items("DEFAULT"):
            max_key_width = max(len(str(key)), max_key_width)
            max_val_width = max(len(str(val)), max_val_width)

        return (str(max_key_width), str(max_val_width))

    def render_text(self, outfd, data):
        outfd.write("\n")
        self.table_header(outfd, [("Option", self.max_width()[0]), ("Value", self.max_width()[1])])
        ## Print out the final saved configuration
        for opt, val in self.new_config.items("DEFAULT"):
            self.table_row(outfd, opt, val)

        if len(self.suglist) > 1:
            outfd.write("\nSuggested profiles: {}\n".format(", ".join(self.suglist)))
        if self.suglist:
            outfd.write("Selected profile: {}\n".format(self.suglist[0]))

        outfd.write("\nConfiguration saved to {}\n".format(self.save_location))
