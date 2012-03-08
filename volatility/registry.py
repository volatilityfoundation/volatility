# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Derived from source in PyFlag developed by:
# Copyright 2004: Commonwealth of Australia.
# Michael Cohen <scudette@users.sourceforge.net> 
# David Collett <daveco@users.sourceforge.net>
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
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

import os, sys, zipfile
import volatility.constants as constants
import volatility.debug as debug
import volatility.conf as conf
config = conf.ConfObject()

config.add_option("INFO", default = None, action = "store_true",
                  cache_invalidator = False,
                  help = "Print information about all registered objects")

config.add_option("PLUGINS", default = "",
                  cache_invalidator = False,
                  help = "Additional plugin directories to use (colon separated)")

class PluginImporter(object):
    """This class searches through a comma-separated list of plugins and
       imports all classes found, based on their path and a fixed prefix.
    """
    def __init__(self, plugins = None):
        """Gathers all the plugins from config.PLUGINS
           Determines their namespaces and maintains a dictionary of modules to filepaths
           Then imports all modules found
        """
        self.modnames = {}

        # Handle the core plugins
        if not plugins:
            plugins = constants.PLUGINPATH
        else:
            plugins += ";" + constants.PLUGINPATH

        # Handle additional plugins
        for path in plugins.split(';'):
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

class MemoryRegistry(object):
    """ Main class to register classes derived from a given parent
    class. 
    """
    ## NOTE - These are class attributes - they will be the same for
    ## all classes, subclasses and future instances of them. They DO
    ## NOT get reset for each instance.
    modules = []
    module_desc = []
    module_paths = []

    def __init__(self, ParentClass):
        """ Search all imported modules for all classes extending
        ParentClass.

        These will be considered as implementations and added to our
        internal registry.  
        """
        ## Create instance variables
        self.classes = []
        self.class_names = []
        self.order = []
        self.ParentClass = ParentClass

        for Class in self.get_subclasses(self.ParentClass):
            if Class != self.ParentClass:
                ## Check the class for consistency
                try:
                    self.check_class(Class)
                    ## Add the class to ourselves:
                    self.add_class(Class)
                except NotImplementedError:
                    pass
                except AttributeError, e:
                    debug.debug("Failed to load {0} '{1}': {2}".format(self.ParentClass, Class, e))
                    continue
            else:
                if hasattr(Class, 'register_options'):
                    Class.register_options(config)

    def get_subclasses(self, cls):
        """Returns a list of all subclasses"""
        for i in cls.__subclasses__():
            for c in self.get_subclasses(i):
                yield c
        yield cls

    def add_class(self, Class):
        """ Adds the class provided to our self. This is here to be
        possibly over ridden by derived classes.
        """
        if Class not in self.classes:
            self.classes.append(Class)

            # Register any config options required by the class
            if hasattr(Class, 'register_options'):
                Class.register_options(config)

            try:
                self.order.append(Class.order)
            except AttributeError:
                self.order.append(10)

    def check_class(self, Class):
        """ Run a set of tests on the class to ensure its ok to use.

        If there is any problem, we chuck an exception.
        """
        prohibited_class_names = ["BufferAddressSpace", "HiveAddressSpace"]
        if Class.__name__.lower().startswith("abstract"):
            raise NotImplementedError("This class is an abstract class")
        if Class.__name__ in prohibited_class_names:
            raise NotImplementedError("This class name is prohibited from the Registry")

class VolatilityCommandRegistry(MemoryRegistry):
    """ A class to manage commands """
    def __getitem__(self, command_name):
        """ Return the command objects by name """
        return self.commands[command_name]

    def __contains__(self, item):
        """ Return whether the item is present in the registry """
        return item in self.commands

    def __init__(self, ParentClass):
        MemoryRegistry.__init__(self, ParentClass)
        self.commands = {}

        for cls in self.classes:
            ## The name of the class is the command name
            command = cls.__name__.split('.')[-1].lower()
            try:
                raise Exception("Command {0} has already been defined by {1}".format(cls, self.commands[command]))
            except KeyError:
                self.commands[command] = cls

class VolatilityObjectRegistry(MemoryRegistry):
    """ A class to manage objects """
    def __getitem__(self, object_name):
        """ Return the objects by name """
        return self.objects[object_name]

    def __contains__(self, item):
        """ Return whether the item is present in the registry """
        return item in self.objects

    def __init__(self, ParentClass):
        MemoryRegistry.__init__(self, ParentClass)
        self.objects = {}

        ## First we sort the classes according to their order
        def sort_function(x, y):
            try:
                a = x.order
            except AttributeError:
                a = 10

            try:
                b = y.order
            except AttributeError:
                b = 10

            if a < b:
                return -1
            elif a == b:
                return 0
            return 1

        self.classes.sort(sort_function)

        for cls in self.classes:
            ## The name of the class is the object name
            obj = cls.__name__.split('.')[-1]
            try:
                raise Exception("Object {0} has already been defined by {1}".format(obj, self.objects[obj]))
            except KeyError:
                self.objects[obj] = cls

def print_info():
    for k, v in globals().items():
        if isinstance(v, MemoryRegistry):
            print "\n"
            print "{0}".format(k)
            print "-" * len(k)

            result = []
            max_length = 0
            for cls in v.classes:
                try:
                    doc = cls.__doc__.strip().splitlines()[0]
                except AttributeError:
                    doc = 'No docs'
                clsname = cls.__name__
                # Convert classes to lower case for plugins so as not to
                # confuse people who attempt to use the classes as the name for plugins
                if isinstance(v, VolatilityCommandRegistry):
                    clsname = cls.__name__.lower()
                result.append((clsname, doc))
                max_length = max(len(clsname), max_length)

            ## Sort the result
            result.sort(key = lambda x: x[0])

            for x in result:
                print "{0:{2}} - {1:15}".format(x[0], x[1], max_length)

LOCK = 0
PLUGIN_COMMANDS = None
OBJECT_CLASSES = None
AS_CLASSES = None
PROFILES = None
SCANNER_CHECKS = None

## This is required for late initialization to avoid dependency nightmare.
def Init():
    ## Load all the modules:
    PluginImporter(config.PLUGINS)

    ## LOCK will ensure that we only initialize once.
    global LOCK
    if LOCK:
        return
    LOCK = 1

    ## Register all shell commands:
    import volatility.commands as commands
    global PLUGIN_COMMANDS
    PLUGIN_COMMANDS = VolatilityCommandRegistry(commands.Command)

    import volatility.addrspace as addrspace
    global AS_CLASSES
    AS_CLASSES = VolatilityObjectRegistry(addrspace.BaseAddressSpace)

    global PROFILES
    import volatility.obj as obj
    PROFILES = VolatilityObjectRegistry(obj.Profile)

    import volatility.scan as scan
    global SCANNER_CHECKS
    SCANNER_CHECKS = VolatilityObjectRegistry(scan.ScannerCheck)

    if config.INFO:
        print_info()
        sys.exit(0)
