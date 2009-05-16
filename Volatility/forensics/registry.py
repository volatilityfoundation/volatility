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
""" This module implements a class registry.

We scan the memory_plugins directory for all python files and add those
classes which should be registered into their own lookup tables. These
are then ordered as required. The rest of Volatility will then call onto the
registered classes when needed.

This mechanism allows us to reorgenise the code according to
functionality. For example we may include a Scanner, Report and File
classes in the same plugin and have them all automatically loaded.
"""

import os,sys,imp
from os.path import dirname, join, normpath

## Define the parameters we need:
PLUGINS = "memory_plugins:memory_objects"

class MemoryRegistry:
    """ Main class to register classes derived from a given parent
    class. 
    """

    modules = []
    module_desc = []
    module_paths = []
    classes = []
    class_names = []
    order = []
    filenames = {}
    
    def __init__(self,ParentClass):
        """ Search the plugins directory for all classes extending
        ParentClass.

        These will be considered as implementations and added to our
        internal registry.  
	"""

        ## Create instance variables
        self.classes = []
        self.class_names = []
        self.order = []
       
        # Get program path
	#basedir = os.path.dirname(sys.argv[0])

        ## Recurse over all the plugin directories recursively
        for path in PLUGINS.split(':'):
	    #path = os.path.join(basedir, path)
            path = os.path.normpath(os.path.join(os.path.dirname(__file__), \
                os.path.join("..", path)))
            for dirpath, dirnames, filenames in os.walk(path):
                sys.path.append(dirpath)
                
                for filename in filenames:
                    #Lose the extension for the module name
                    module_name = filename[:-3]
                    if filename.endswith(".py"):
                        path = os.path.join(dirpath, filename)
                        try:
                            if path not in self.module_paths:
                                ## If we do not have the module in the 
                                ## cache, we load it now
                                try:
                                    #open the plugin file
                                    fd = open(path ,"r")
                                except Exception,e:
                                    print "Unable to open plugin file '%s': %s"% (filename,e)
                                    continue

                                #load the module into our namespace
                                try:
                                    ## Try to load the module from the
                                    ## currently cached copy
                                    try:
                                        module = sys.modules[module_name]
                                    except KeyError:
                                        module = imp.load_source(module_name,dirpath+'/'+filename,fd)
                                except Exception,e:
                                    print "*** Unable to load module %s: %s" % (module_name,e)
                                    continue

                                fd.close()

                                #Is this module active?
                                try:
                                    if module.hidden:
                                        print "*** Will not load Module %s: Module Hidden"% (module_name)
                                        continue
                                except AttributeError:
                                    pass
                                
                                try:
                                    if not module.active:
                                        print "*** Will not load Module %s: Module not active" % (module_name)
                                        continue
                                except AttributeError:
                                    pass
                                
                                #find the module description
                                try:
                                    module_desc = module.description
                                except AttributeError:
                                    module_desc = module_name

                                ## Store information about this module here.
                                self.modules.append(module)
                                self.module_desc.append(module_desc)
                                self.module_paths.append(path)
                                
                            else:
                                ## We already have the module in the cache:
                                module = self.modules[self.module_paths.index(path)]
                                module_desc = self.module_desc[self.module_paths.index(path)]

                            #Now we enumerate all the classes in the
                            #module to see which one is a ParentClass:
                            for cls in dir(module):
                                try:
                                    Class = module.__dict__[cls]
                                    if issubclass(Class,ParentClass) and Class!=ParentClass:
                                        ## Check the class for consitancy
                                        try:
                                            self.check_class(Class)
                                        except AttributeError,e:
                                            print "Failed to load %s '%s': %s" % (ParentClass,cls,e)
                                            continue

                                        ## Add the class to ourselves:
                                        self.add_class(ParentClass, module_desc, cls, Class, filename)
                                            
                                # Oops: it isnt a class...
                                except (TypeError, NameError) , e:
                                    continue

                        except TypeError, e:
                            print "Could not compile module %s: %s"% (module_name,e)
                            continue

    def add_class(self, ParentClass, module_desc, cls, Class, filename):
        """ Adds the class provided to our self. This is here to be
        possibly over ridden by derived classes.
        """
        if Class not in self.classes:
            self.classes.append(Class)
            self.filenames[self.get_name(Class)] = filename
            try:
                self.order.append(Class.order)
            except:
                self.order.append(10)

    def check_class(self,Class):
        """ Run a set of tests on the class to ensure its ok to use.

        If there is any problem, we chuck an exception.
        """

    def import_module(self,name=None,load_as=None):
        """ Loads the named module into the system module name space.
        After calling this it is possible to do:

        import load_as

        in all other modules. Note that to avoid race conditions its
        best to only attempt to use the module after the registry is
        initialised (i.e. at run time not load time).

        @arg load_as: name to use in the systems namespace.
        @arg name: module name to import
        @note: If there are several modules of the same name (which
        should be avoided)  the last one encountered during registring
        should persist. This may lead to indeterminate behaviour.  
	"""

        if not load_as: load_as=name
        
        for module in self.modules:
            if name==module.__name__:
                sys.modules[load_as] = module
                return

        raise ImportError("No module by name %s" % name)

    def get_name(self, cls):
        try:
            return cls.name
        except AttributeError:
            return ("%s" % cls).split(".")[-1]

    def filename(self, cls_name):
        return self.filenames.get(cls_name, "Unknown")

class VolatilityCommandRegistry(MemoryRegistry):
    """ A class to manage commands """
    commands = {}
    def __getitem__(self,command_name):
        """ Return the command objects by name """
        return self.commands[command_name]
    
    def __init__(self,ParentClass):
        MemoryRegistry.__init__(self,ParentClass)
        for cls in self.classes:
            ## The name of the class is the command name
            command = ("%s" % cls).split('.')[-1]
            try:
                raise Exception("Command %s has already been defined by %s" % (command,self.commands[command]))
            except KeyError:
                self.commands[command]=cls

class VolatilityObjectRegistry(MemoryRegistry):
    """ A class to manage objects """
    objects = {}
    def __getitem__(self,object_name):
        """ Return the objects by name """
        return self.objects[object_name]
    
    def __init__(self,ParentClass):
        MemoryRegistry.__init__(self,ParentClass)
        for cls in self.classes:
            ## The name of the class is the object name
            #obj = ("%s" % cls).split()[-1]
            #obj = obj[1:-2]
            obj = cls.__name__
            try:
                raise Exception("Object %s has already been defined by %s" % (obj,self.objects[obj]))
            except KeyError:
                self.objects[obj]=cls


LOCK = 0
PLUGIN_COMMANDS = None
OBJECT_CLASSES = None

## This is required for late initialization to avoid dependency nightmare.
def Init():
    ## LOCK will ensure that we only initialize once.
    global LOCK
    if LOCK:
        return
    LOCK=1

    ## Register all shell commands:
    import forensics.commands as commands
    global PLUGIN_COMMANDS
    PLUGIN_COMMANDS = VolatilityCommandRegistry(commands.command)

    ## Register all the derived objects
    import forensics.object2 as object2
    global OBJECT_CLASSES
    OBJECT_CLASSES = VolatilityObjectRegistry(object2.Object)
