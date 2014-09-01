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

config = conf.ConfObject()

class SaveConfig(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        config.add_option("SAVE-FILE", default = 'volatilityrc',
            cache_invalidator = False, help = "User based configuration file")


    def calculate(self):
        
        new_config = ConfigParser.RawConfigParser()
        save_location = 'volatilityrc'
        for key in self._config.cnf_opts:
            print(key, self._config.cnf_opts[key])
            new_config.set('DEFAULT', str(key), str(self._config.cnf_opts[key]))
        
        with open(save_location, 'wb') as configfile:
            new_config.write(configfile)
            print("Saved command line options to " + save_location)

    def render_text(self, outfd, data):
        pass


