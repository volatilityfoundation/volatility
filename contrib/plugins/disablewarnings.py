# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
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
