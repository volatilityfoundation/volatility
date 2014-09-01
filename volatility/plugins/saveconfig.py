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
import ConfigParser

class SaveConfig(common.AbstractWindowsCommand):
    """Generates Volatility configuration files"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option("DEST", default = "./volatilityrc", short_option = "D",
            help = "Destination of saved configuration file")

        config.add_option("EXCLUDE-CONF", default = False, short_option = "E",
            action = "store_true", help = "Exclude settings from configuration files")

        config.add_option("MODIFY", default = False, short_option = "M",
            action = "store_true", help = "Modify (rather than override) the generated configuration file")

        ## Used to make sure we don"t save our own options and options that are already saved
        self._exclude_options = ["dest", "exclude_conf", "modify"]

    def calculate(self):
        self.new_config = ConfigParser.RawConfigParser()
        self.save_location = self._config.DEST

        ## Read from existing target configuration (if modifying)
        if self._config.MODIFY:
            self.new_config.read(self.save_location)

        ## Save current command line options first (these take precedence)
        for key in self._config.opts:
            if key not in self._exclude_options:
                self.new_config.set("DEFAULT", key, self._config.opts[key])
                ## Add to excluded list so we don"t overwrite them later
                self._exclude_options.append(key)

        ## Save options from configuration files (unless excluded by user)
        if self._config.EXCLUDE_CONF == False:
            for key in self._config.cnf_opts:
                if key not in self._exclude_options:
                    self.new_config.set("DEFAULT", key, self._config.cnf_opts[key])

        ## Write the actual configuration file
        with open(self.save_location, "wb") as configfile:
            self.new_config.write(configfile)

    def render_text(self, outfd, data):
        outfd.write("\n")
        self.table_header(outfd, [("Option", "20"), ("Value", "75")])

        ## Print out the final saved configuration
        for opt, val in self.new_config.items("DEFAULT"):
            self.table_row(outfd, opt, val)

        outfd.write("\nConfiguration saved to {}\n".format(self.save_location))
