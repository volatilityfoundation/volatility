#!/usr/bin/env python

# Volatility
# 
# Authors:
# AAron Walters <awalters@4tphi.net>
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

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import volatility.constants
import sys
import os

py2exe_available = True
try:
    import py2exe #pylint: disable-msg=W0611,F0401
except ImportError:
    py2exe_available = False

def find_files(topdirs, py = False):
    """Lists all python files under any topdir from the topdirs lists.
    
       Returns an appropriate list for data_files,
       with source and destination directories the same"""
    ret = []
    for topdir in topdirs:
        for r, _ds, fs in os.walk(topdir):
            ret.append((r, [ os.path.join(r, f) for f in fs if (f.endswith('.py') or not py)]))
    return ret

opts = {}

opts['name'] = "volatility"
opts['version'] = volatility.constants.VERSION
opts['description'] = "Volatility -- Volatile memory framwork"
opts['author'] = "AAron Walters"
opts['author_email'] = "awalters@4tphi.net"
opts['url'] = "http://www.volatilityfoundation.org"
opts['license'] = "GPL"
opts['scripts'] = ["vol.py"]
opts['packages'] = ["volatility",
                    "volatility.win32",
                    "volatility.plugins",
                    "volatility.plugins.addrspaces",
                    "volatility.plugins.overlays",
                    "volatility.plugins.overlays.windows",
                    "volatility.plugins.overlays.linux",
                    "volatility.plugins.overlays.mac",
                    "volatility.plugins.gui",
                    "volatility.plugins.gui.vtypes",
                    "volatility.plugins.linux",
                    "volatility.plugins.registry",
                    "volatility.plugins.malware", 
                    "volatility.plugins.mac"]
opts['data_files'] = find_files(['contrib'], py = True) + find_files(['tools'])

if py2exe_available:
    py2exe_distdir = 'dist/py2exe'
    opts['console'] = [{ 'script': 'vol.py',
                         'icon_resources': [(1, 'resources/volatility.ico')]
                      }]
    # Optimize must be 1 for plugins that use docstring for the help value,
    # otherwise the help gets optimized out
    opts['options'] = {'py2exe':{'optimize': 1,
                                 'dist_dir': py2exe_distdir,
                                 'packages': opts['packages'] + ['socket', 'ctypes', 'Crypto.Cipher', 'urllib', 'distorm3', 'yara', 'xml.etree.ElementTree'],
                                 # This, along with zipfile = None, ensures a single binary
                                 'bundle_files': 1,
                                }
                      }
    opts['zipfile'] = None

distrib = setup(**opts) #pylint: disable-msg=W0142

if 'py2exe' in sys.argv:
    # Any py2exe specific files or things that need doing can go in here
    pass
