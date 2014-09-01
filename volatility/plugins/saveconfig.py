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

#import volatility.obj as obj
#import volatility.scan as scan
#import volatility.cache as cache
import volatility.plugins.common as common
import volatility.conf as conf
#import volatility.addrspace as addrspace
#import volatility.registry as registry
#import volatility.utils as utils
#import volatility.exceptions as exceptions
import ConfigParser
#import os
#import sys


class SaveConfig(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option("DEST", default = './volatilityrc', short_option = "D",
            help = "Destination of saved configuration file")

        config.add_option('EXCLUDE-CONF', default = False, short_option = "E",
            action = "store_true", help = "Exclude settings from configuration files")

        ## Used to make sure we don't save our own options
        self._own_options = ["dest", "exclude_conf"]

    def calculate(self):
        help( self._config)
        new_config = ConfigParser.RawConfigParser()
        self.save_location = self._config.DEST

        ## Save options from configuration files
        if self._config.EXCLUDE_CONF == False:
            for key in self._config.cnf_opts:
                yield key, self._config.cnf_opts[key]
                new_config.set('DEFAULT', str(key), str(self._config.cnf_opts[key]))


        ## Save current command line options
        for key in self._config.opts:
            if key not in self._own_options:
                yield key, self._config.opts[key]
                new_config.set('DEFAULT', str(key), str(self._config.opts[key]))

        with open(self.save_location, 'wb') as configfile:
            new_config.write(configfile)

    def render_text(self, outfd, data):
        outfd.write("\n")
        self.table_header(outfd, [("Option", "20"), ("Value", "75")])
        for option in data:
            self.table_row(outfd, str(option[0]), str(option[1]))
            #outfd.write("{0}\t=\t{1}\n".format(option[0], option[1]))
        outfd.write("\nConfiguration saved to {}\n".format(self.save_location))
