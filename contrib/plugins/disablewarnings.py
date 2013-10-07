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

import volatility.conf as conf
import logging

config = conf.ConfObject()

def disable_warnings(_option, _opt_str, _value, _parser):
    """Sets the location variable in the parser to the filename in question"""
    rootlogger = logging.getLogger('')
    rootlogger.setLevel(logging.WARNING + 1)

config.add_option("WARNINGS", default = False, action = "callback",
                  callback = disable_warnings,
                  short_option = 'W', nargs = 0,
                  help = "Disable warning messages")
