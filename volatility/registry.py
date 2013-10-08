# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# Derived from source in PyFlag developed by:
# Copyright 2004: Commonwealth of Australia.
# Michael Cohen <scudette@users.sourceforge.net> 
# David Collett <daveco@users.sourceforge.net>
#
# Subclassing plugin code developed by:
#
# Mike Auty <mike.auty@gmail.com>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
# *****************************************************

#pylint: disable-msg=C0111

""" This module implements a class registry.

We scan the memory_plugins directory for all python files and add those
classes which should be registered into their own lookup tables. These
are then ordered as required. The rest of Volatility will then call onto the
registered classes when needed.

This mechanism allows us to reorganise the code according to
functionality. For example we may include a Scanner, Report and File
classes in the same plugin and have them all automatically loaded.
"""

import os, zipfile
import volatility.debug as debug
import volatility.plugins as plugins

class PluginImporter(object):
    """This class searches through a comma-separated list of plugins and
       imports all classes found, based on their path and a fixed prefix.
    """
    def __init__(self):
        """Gathers all the plugins from config.PLUGINS
           Determines their namespaces and maintains a dictionary of modules to filepaths
           Then imports all modules found
        """
        self.modnames = {}

        # Handle additional plugins
        for path in plugins.__path__:
            path = os.path.abspath(path)

            for relfile in self.walkzip(path):
                module_path, ext = os.path.splitext(relfile)
                namespace = ".".join(['volatility.plugins'] + [ x for x in module_path.split(os.path.sep) if x ])
                #Lose the extension for the module name
                if ext in [".py", ".pyc", ".pyo"]:
                    filepath = os.path.join(path, relfile)
                    # Handle Init files
                    initstr = '.__init__'
                    if namespace.endswith(initstr):
                        self.modnames[namespace[:-len(initstr)]] = filepath
                    else:
                        self.modnames[namespace] = filepath

        self.run_imports()

    def walkzip(self, path):
        """Walks a path independent of whether it includes a zipfile or not"""
        if os.path.exists(path) and os.path.isdir(path):
            for dirpath, _dirnames, filenames in os.walk(path):
                for filename in filenames:
                    # Run through files as we always used to
                    yield os.path.join(dirpath[len(path) + len(os.path.sep):], filename)
        else:
            index = -1
            zippath = None
            while path.find(os.path.sep, index + 1) > -1:
                index = path.find(os.path.sep, index + 1)
                if zipfile.is_zipfile(path[:index]):
                    zippath = path[:index]
                    break
            else:
                if zipfile.is_zipfile(path):
                    zippath = path

            # Now yield the files
            if zippath:
                zipf = zipfile.ZipFile(zippath)
                prefix = path[len(zippath):].strip(os.path.sep)
                # If there's a prefix, ensure it ends in a slash
                if len(prefix):
                    prefix += os.path.sep
                for fn in zipf.namelist():
                    # Zipfiles seem to always list contents using / as their separator
                    fn = fn.replace('/', os.path.sep)
                    if fn.startswith(prefix) and not fn.endswith(os.path.sep):
                        # We're a file in the zipfile
                        yield fn[len(prefix):]

    def run_imports(self):
        """Imports all the already found modules"""
        for i in self.modnames.keys():
            if self.modnames[i] is not None:
                try:
                    __import__(i)
                except Exception, e:
                    print "*** Failed to import " + i + " (" + str(e.__class__.__name__) + ": " + str(e) + ")"
                    # This is too early to have had the debug filter lowered to include debugging messages
                    debug.post_mortem(2)

def _get_subclasses(cls):
    """ Run through subclasses of a particular class

        This returns all classes descended from the main class,
        _including_ the main class itself.  If showall is set to
        False (the default) then classes starting with Abstract 
        will not be returned.
    """
    for i in cls.__subclasses__():
        for c in _get_subclasses(i):
            yield c
    yield cls

def get_plugin_classes(cls, showall = False, lower = False):
    """Returns a dictionary of plugins"""
    # Plugins all make use of the Abstract concept
    result = {}
    for plugin in set(_get_subclasses(cls)):
        if showall or not (plugin.__name__.startswith("Abstract") or plugin == cls):
            # FIXME: This is due to not having done things correctly at the start
            if not showall and plugin.__name__ in ['BufferAddressSpace', 'HiveFileAddressSpace', 'HiveAddressSpace']:
                continue
            name = plugin.__name__.split('.')[-1]
            if lower:
                name = name.lower()
            if name not in result:
                result[name] = plugin
            else:
                raise Exception("Object {0} has already been defined by {1}".format(name, plugin))
    return result

def register_global_options(config, cls):
    ## Register all register_options for the various classes
    for m in get_plugin_classes(cls, True).values():
        if hasattr(m, 'register_options'):
            m.register_options(config)
