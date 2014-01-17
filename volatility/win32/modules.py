# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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

"""
@author:       AAron Walters and Nick Petroni
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net, npetroni@4tphi.net
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111
import volatility.win32.tasks as tasks

def lsmod(addr_space):
    """ A Generator for modules """

    for m in tasks.get_kdbg(addr_space).modules():
        yield m
