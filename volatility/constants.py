# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
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

# Blocksize was chosen to make it aligned
# on 8 bytes
# Optimized by Michael Cohen

import os, sys

VERSION = "2.3"

SCAN_BLOCKSIZE = 1024 * 1024 * 10

PLUGINPATH = os.path.dirname(__file__)
# If we're in a pyinstaller executable 
if hasattr(sys, "frozen"):
    try:
        PLUGINPATH = sys._MEIPASS #pylint: disable-msg=W0212,E1101
    except ImportError:
        pass
PLUGINPATH = os.path.join(PLUGINPATH, 'plugins')
