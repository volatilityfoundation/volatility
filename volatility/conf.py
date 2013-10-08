## This file was taken from PyFlag http://www.pyflag.net/
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
# ******************************************************

#pylint: disable-msg=C0111

""" Configuration modules for pyflag.

PyFlag is a complex package and requires a flexible configuration
system. The following are the requirements of the configuration
system:

1) Configuration must be available from a number of sources:

   - Autoconf must be able to set things like the python path (in case
     pyflag is installed to a different prefix)
     
   - Users must be able to configure the installed system for their
   specific requirements.

   - Unconfigured parameters must be resolved at run time through the
   GUI and saved.

2) Configuration must be able to apply to cases specifically.

3) Because pyflag is modular, configuration variables might be required
   for each module. This means that definitions and declarations of
   configuration variables must be distributed in each plugin.

These goals are achieved by the use of multiple sources of
configuration information:

   - The system wide configuration file is this file: conf.py. It is
   generated from the build system from conf.py.in by substituting
   autoconfigured variables into it. It contains the most basic
   settings related to the installation, e.g. which python interpreted
   is used, where the python modules are installed etc. In particular
   it refers to the location of the system configuration file (usually
   found in /usr/local/etc/pyflagrc, or in /etc/pyflagrc).

   - The sysconfig file contains things like where the upload
   directory is, where to store temporary files etc. These are mainly
   installation wide settings which are expected to be modified by the
   administrator. Note that if you want the GUI to manipulate this
   file it needs to be writable by the user running the GUI.

   - Finally a conf table in each case is used to provide a per case
   configuration
   
"""
import ConfigParser
import optparse
import os
import sys

default_config = "/etc/volatilityrc"

class PyFlagOptionParser(optparse.OptionParser):
    final = False
    help_hooks = []

    def _process_args(self, largs, rargs, values):
        try:
            return optparse.OptionParser._process_args(self, largs, rargs, values)
        except (optparse.BadOptionError, optparse.OptionValueError), err:
            if self.final:
                raise err

    def error(self, msg):
        ## We cant emit errors about missing parameters until we are
        ## sure that all modules have registered all their parameters
        if self.final:
            return optparse.OptionParser.error(self, msg)
        else:
            raise RuntimeError(msg)

    def print_help(self, file = sys.stdout):
        optparse.OptionParser.print_help(self, file)

        for cb in self.help_hooks:
            file.write(cb())

class ConfObject(object):
    """ This is a singleton class to manage the configuration.

    This means it can be instantiated many times, but each instance
    refers to the global configuration (which is set in class
    variables).

    NOTE: The class attributes have static dicts assigned to
    facilitate singleton behaviour. This means all future instances
    will have the same dicts.
    """
    optparser = PyFlagOptionParser(add_help_option = False,
                                   version = False,
                                   )
    initialised = False

    ## This is the globals dictionary which will be used for
    ## evaluating the configuration directives.
    g_dict = dict(__builtins__ = None)

    ## These are the options derived by reading any config files
    cnf_opts = {}

    ## Command line opts
    opts = {}
    args = None
    default_opts = {}
    docstrings = {}

    ## These are the actual options returned by the optparser:
    optparse_opts = None

    ## Filename where the configuration file is:
    _filename = None

    _filenames = []

    ## These parameters can not be updated by the GUI (but will be
    ## propagated into new configuration files)
    readonly = {}

    ## Absolute parameters can only be set by the code or command
    ## lines, they can not be over ridden in the configuration
    ## file. This ensures that only configuration files dont mask new
    ## options (e.g. schema version)
    _absolute = {}

    ## A list of option names:
    options = []

    ## Cache variants: There are configuration options which
    ## encapsulate the state of the running program. If any of these
    ## change all caches will be invalidated.
    cache_invalidators = {}

    def __init__(self):
        """ This is a singleton object kept in the class """
        if not ConfObject.initialised:
            self.optparser.add_option("-h", "--help", action = "store_true", default = False,
                            help = "list all available options and their default values. Default values may be set in the configuration file (" + default_config + ")")

            ConfObject.initialised = True

    def set_usage(self, usage = None, version = None):
        if usage:
            self.optparser.set_usage(usage)

        if version:
            self.optparser.version = version

    def add_file(self, filename, _type = 'init'):
        """ Adds a new file to parse """
        self._filenames.append(filename)

        self.cnf_opts.clear()

        for f in self._filenames:
            try:
                conf_parser = ConfigParser.ConfigParser()
                conf_parser.read(f)

                for k, v in conf_parser.items('DEFAULT'):
                    ## Absolute parameters are protected from
                    ## configuration files:
                    if k in self._absolute.keys():
                        continue

                    try:
                        v = eval(v, self.g_dict)
                    except Exception, _e:
                        pass

                    ## update the configured options
                    self.cnf_opts[k] = v

            except IOError:
                print "Unable to open {0}".format(f)

        ConfObject._filename = filename

    def print_help(self):
        return self.optparser.print_help()

    def add_help_hook(self, cb):
        """ Adds an epilog to the help message """
        self.optparser.help_hooks.append(cb)

    def set_help_hook(self, cb):
        self.optparser.help_hooks = [cb]

    def parse_options(self, final = True):
        """ Parses the options from command line and any conf files
        currently added.

        The final parameter should be only called from main programs
        at the point where they are prepared for us to call exit if
        required; (For example when we detect the -h parameter).
        """
        self.optparser.final = final

        ## Parse the command line options:
        try:
            (opts, args) = self.optparser.parse_args()

            self.opts.clear()

            ## Update our cmdline dict:
            for k in dir(opts):
                v = getattr(opts, k)
                if k in self.options and not v == None:
                    self.opts[k] = v

        except UnboundLocalError:
            raise RuntimeError("Unknown option - use -h to see help")

        ## If error() was called we catch it here
        except RuntimeError:
            opts = {}
            ## This gives us as much as was parsed so far
            args = self.optparser.largs

        self.optparse_opts = opts
        self.args = args

        if final:
            ## Reparse the config file again:
            self.add_file(self._filename)

            try:
                ## Help can only be set on the command line
                if getattr(self.optparse_opts, "help"):

                ## Populate the metavars with the default values:
                    for opt in self.optparser.option_list:
                        try:
                            opt.metavar = "{0}".format((getattr(self, opt.dest) or
                                                        opt.dest.upper()))
                        except Exception, _e:
                            pass

                    self.optparser.print_help()
                    sys.exit(0)
            except AttributeError:
                pass

            ## Set the cache invalidators on the cache now:
            import volatility.cache as cache
            for k, v in self.cache_invalidators.items():
                cache.CACHE.invalidate_on(k, v)

    def remove_option(self, option):
        """ Removes options both from the config file parser and the
            command line parser

            This should only by used on options *before* they have been read,
            otherwise things could get very confusing.
        """
        option = option.lower()

        if option in self.cache_invalidators:
            del self.cache_invalidators[option]

        normalized_option = option.replace("-", "_")

        if normalized_option not in self.options:
            return

        self.options.remove(normalized_option)

        if normalized_option in self.readonly:
            del self.readonly[normalized_option]

        if normalized_option in self.default_opts:
            del self.default_opts[normalized_option]

        if normalized_option in self._absolute:
            del self._absolute[normalized_option]

        del self.docstrings[normalized_option]

        self.optparser.remove_option("--{0}".format(option))

        try:
            self.parse_options(False)
        except AttributeError:
            pass

    def add_option(self, option, short_option = None,
                   cache_invalidator = True,
                   **args):
        """ Adds options both to the config file parser and the
        command line parser.

        Args:
          option:            The long option name.
          short_option:      An optional short option.
          cache_invalidator: If set, when this option
                             changes all caches are invalidated.
        """
        option = option.lower()

        if cache_invalidator:
            self.cache_invalidators[option] = lambda : self.get_value(option)

        normalized_option = option.replace("-", "_")

        if normalized_option in self.options:
            return

        self.options.append(normalized_option)

        ## If this is read only we store it in a special dict
        try:
            if args['readonly']:
                self.readonly[normalized_option] = args['default']
            del args['readonly']
        except KeyError:
            pass

        ## If there is a default specified, we update our defaults dict:
        try:
            default = args['default']
            try:
                default = eval(default, self.g_dict)
            except:
                pass

            self.default_opts[normalized_option] = default
            del args['default']
        except KeyError:
            pass

        try:
            self._absolute[normalized_option] = args['absolute']
            del args['absolute']
        except KeyError:
            pass

        self.docstrings[normalized_option] = args.get('help', None)

        if short_option:
            self.optparser.add_option("-{0}".format(short_option), "--{0}".format(option), **args)
        else:
            self.optparser.add_option("--{0}".format(option), **args)

        ## update the command line parser

        ## We have to do the try-catch for python 2.4 support of short
        ## arguments. It can be removed when python 2.5 is a requirement
        try:
            self.parse_options(False)
        except AttributeError:
            pass

    def update(self, key, value):
        """ This can be used by scripts to force a value of an option """
        self.readonly[key.lower()] = value

    def get_value(self, key):
        return getattr(self, key.replace("-", "_"))

    def __getattr__(self, attr):
        ## If someone is looking for a configuration parameter but
        ## we have not parsed anything yet - do so now.
        if self.opts == None:
            self.parse_options(False)

        ## Maybe its a class method?
        try:
            return super(ConfObject, self).__getattribute__(attr)
        except AttributeError:
            pass

        ## Is it a ready only parameter (i.e. can not be overridden by
        ## the config file)
        try:
            return self.readonly[attr.lower()]
        except KeyError:
            pass

        ## Try to find the attribute in the command line options:
        try:
            return self.opts[attr.lower()]
        except KeyError:
            pass

        ## Has it already been parsed?
        try:
            tmp = getattr(self.optparser.values, attr.lower())
            if tmp:
                return tmp
        except AttributeError:
            pass

        ## Was it given in the environment?
        try:
            return os.environ["VOLATILITY_" + attr.upper()]
        except KeyError:
            pass

        ## No - try the configuration file:
        try:
            return self.cnf_opts[attr.lower()]
        except KeyError:
            pass

        ## No - is there a default for it?
        try:
            return self.default_opts[attr.lower()]
        except KeyError:
            pass

        ## Maybe its just a command line option:
        try:
            if not attr.startswith("_") and self.optparse_opts:
                return getattr(self.optparse_opts, attr.lower())
        except AttributeError:
            pass

        raise AttributeError("Parameter {0} is not configured - try setting it on the command line (-h for help)".format(attr))

class DummyConfig(ConfObject):
    pass

config = ConfObject()
if os.access(default_config, os.R_OK):
    config.add_file(default_config)
else:
    config.add_file("volatilityrc")

default_conf_path = ".volatilityrc"
try:
    default_conf_path = os.environ['HOME'] + '/.volatilityrc'
except KeyError:
    pass

config.add_option("CONF-FILE", default = default_conf_path,
                  cache_invalidator = False,
                  help = "User based configuration file")

config.add_file(config.CONF_FILE)
