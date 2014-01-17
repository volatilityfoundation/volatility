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

import sys
import itertools
import timeit

class ScanProfInstance(object):
    def __init__(self, func, *args):
        self.func = func
        self.args = args
        self.results = []

    def __call__(self):
        self.results = self.func(*self.args)

def permscan(self, address_space, offset = 0, maxlen = None):
    times = []
    # Run a warm-up scan to ensure the file is cached as much as possible
    self.oldscan(address_space, offset, maxlen)

    perms = list(itertools.permutations(self.checks))
    for i in range(len(perms)):
        self.checks = perms[i]
        print "Running scan {0}/{1}...".format(i + 1, len(perms))
        profobj = ScanProfInstance(self.oldscan, address_space, offset, maxlen)
        value = timeit.timeit(profobj, number = self.repeats)
        times.append((value, len(list(profobj.results)), i))

    print "Scan results"
    print "{0:20} | {1:7} | {2:6} | {3}".format("Time", "Results", "Perm #", "Ordering")
    for val, l, ordering in sorted(times):
        print "{0:20} | {1:7} | {2:6} | {3}".format(val, l, ordering, perms[ordering])
    sys.exit(1)

def ScanProfiler(cls, repeats = 3):
    cls.repeats = repeats
    cls.oldscan = cls.scan
    cls.scan = permscan
    return cls
