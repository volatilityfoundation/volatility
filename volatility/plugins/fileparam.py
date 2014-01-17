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

import volatility.conf as conf
import urllib
import sys
import os
## This is required to ensure that LOCATION is defined here
import volatility.debug as debug
import volatility.addrspace as addrspace #pylint: disable-msg=W0611

config = conf.ConfObject()

def set_location(_option, _opt_str, value, parser):
    """Sets the location variable in the parser to the filename in question"""
    if not os.path.exists(os.path.abspath(value)):
        debug.error("The requested file doesn't exist")
    if parser.values.location == None:
        slashes = "//"
        # Windows pathname2url decides to convert C:\blah to ///C:/blah
        # So to keep the URLs correct, we only add file: rather than file://
        if sys.platform.startswith('win'):
            slashes = ""
        parser.values.location = "file:" + slashes + urllib.pathname2url(os.path.abspath(value))

config.add_option("FILENAME", default = None, action = "callback",
                  callback = set_location, type = 'str',
                  short_option = 'f', nargs = 1,
                  help = "Filename to use when opening an image")
