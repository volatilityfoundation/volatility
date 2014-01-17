#!/usr/bin/env python
#  -*- mode: python; -*-
#
# Volatility
# Authors:
#   Brendan Dolan-Gavitt
#   Mike Auty
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
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 
@contact:      brendandg@gatech.edu
@organization: Georgia Institute of Technology
"""

from optparse import OptionParser
import hashlib, os, sys

class VtypeHolder(object):

    unstable_var_prefix = "unknown_"

    def __init__(self):
        self.vtypes = None
        self.arrayname = None
        self.filename = None
        self.namemap = {}
        self.dellist = []
        self.basis = None

    def _rename_types(self, vtypes, namemap):
        # Apply the namemap within the types 
        for t in vtypes:
            for m in vtypes[t][1]:
                memb = vtypes[t][1][m]
                d = self._get_deepest(memb)
                if d in namemap:
                    vtypes[t][1][m] = self._deep_replace(memb, d, namemap[d])

        # Rename the types themselves
        for n in namemap:
            if n in vtypes:
                vtypes[namemap[n]] = vtypes[n]
                del vtypes[n]

        return vtypes

    def _deep_replace(self, t, search, repl):
        if t == search:
            return repl
        elif isinstance(t, list):
            return [self._deep_replace(x, search, repl) for x in t]
        else:
            return t

    def _get_deepest(self, t):
        if isinstance(t, list):
            if len(t) == 1:
                return t[0]
            else:
                for part in t:
                    res = self._get_deepest(part)
                    if res:
                        return res
                return None
        return None

    def _tuplify(self, types, t):
        if isinstance(t, list) or isinstance(t, tuple):
            return tuple(sorted([self._tuplify(types, x) for x in t]))
        elif isinstance(t, dict):
            return self._tuplify(types, t.items())
        elif isinstance(t, str) and t.startswith(self.unstable_var_prefix):
            return self._tuplify(types, types[t])
        else:
            return t

    def as_string(self, msizes = True):
        if not self.vtypes:
            return ""

        arrayname = self.arrayname
        if self.basis:
            arrayname += "_additions"

        output = arrayname + " = {\n"
        for t in sorted(self.vtypes):
            output += "  '{0}': [ {1:#x}, {{\n".format(t, self.vtypes[t][0])
            for m in sorted(self.vtypes[t][1], key = lambda m: self.vtypes[t][1][m][0]):
                if msizes:
                    output += "    '{0}': [{1:#x}, {2}],\n".format(m, self.vtypes[t][1][m][0], self.vtypes[t][1][m][1])
                else:
                    output += "    '{0}': [None, {1}],\n".format(m, self.vtypes[t][1][m][1])
            output += "   }],\n"
        output += "}\n"


        if self.basis:
            fn, an = self.basis
            fn = os.path.splitext(os.path.basename(fn))[0]
            output += "\n# We must use deepcopy to avoid overlays affecting multiple profiles\nimport copy\n"
            output += "import {0}\n".format(fn)
            output += "{0} = copy.deepcopy({1}.{2})\n".format(self.arrayname, fn, an)
            if self.dellist:
                for i in self.dellist:
                    output += "del {0}['{1}']\n".format(self.arrayname, i)
            output += "{0}.update({1})\n".format(self.arrayname, arrayname)

        return output

    def load(self, filename):
        self.filename = filename
        locs, globs = {}, {}
        execfile(filename, globs, locs)
        for i in locs.keys():
            if i.endswith('_types'):
                self.arrayname = i
        self.vtypes = locs[self.arrayname]

    def canonicalize(self):
        if not self.vtypes:
            return False
        namemap = {}
        unnamed = [t for t in self.vtypes if t.startswith(self.unstable_var_prefix)]

        # Create the namemap
        for t in unnamed:
            newname = "__volstablename_" + hashlib.md5(str(self._tuplify(self.vtypes, self.vtypes[t]))).hexdigest() #pylint: disable-msg=E1101
            if t in namemap:
                print "Conflicting names for {0}: {1} and {2}".format(t, newname, self.namemap[t])
            if newname in self.vtypes:
                print "Constructed name for {0} ({1}) already exists in vtypes".format(t, newname)
            namemap[t] = newname

        self.namemap = namemap
        self.vtypes = self._rename_types(self.vtypes, namemap)

    def decanonicalize(self, namemap = None):
        if not self.vtypes:
            return False
        if not namemap:
            namemap = self.namemap

        # reverse the namemap
        newnamemap = {}
        for i in namemap:
            newnamemap[namemap[i]] = i

        # Rename the types
        self.vtypes = self._rename_types(self.vtypes, newnamemap)

        # Rename the dellist members
        dellist = [ newnamemap[x] if x in newnamemap else x for x in self.dellist]
        self.dellist = dellist

    def diff(self, base):
        """Compresses these vtypes based on another vtypes"""
        self.basis = base.filename, base.arrayname
        removelist = []
        for i in base.vtypes:
            if i in self.vtypes:
                inithash = hashlib.md5(str(self._tuplify(base.vtypes, base.vtypes[i]))).hexdigest() #pylint: disable-msg=E1101
                diffhash = hashlib.md5(str(self._tuplify(self.vtypes, self.vtypes[i]))).hexdigest() #pylint: disable-msg=E1101
                if inithash == diffhash:
                    removelist.append(i)
            else:
                self.dellist.append(i)
        for i in removelist:
            del self.vtypes[i]

if __name__ == '__main__':
    usage = "usage: %prog [options] <file1> <file2>"
    parser = OptionParser(usage = usage)
    (opts, args) = parser.parse_args()

    if len(args) != 2:
        parser.error("Must provide both vtypes files.")

    # Ensure these can import any modules they require
    sys.path.append(os.path.dirname(args[0]))
    sys.path.append(os.path.dirname(args[1]))

    ### Rename 1
    v1 = VtypeHolder()
    v1.load(args[0])
    v1.canonicalize()
    ### Rename 2
    v2 = VtypeHolder()
    v2.load(args[1])
    v2.canonicalize()
    ### Compress
    v2.diff(v1)
    v2.decanonicalize(v1.namemap)
    # Verify that no two names map to the same value
    for conflict in v1.namemap:
        if conflict in v2.namemap:
            if v1.namemap[conflict] != v2.namemap[conflict]:
                ### Remove possible conflicting unnamed offsets in original naming convention
                del v2.namemap[conflict]
    v2.decanonicalize(v2.namemap)
    ### Print types
    print v2.as_string()
