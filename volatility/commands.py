# Volatility
# Copyright (C) 2008 Volatile Systems
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#


import sys, textwrap

class Command(object):
    """ Base class for each plugin command """
    op = ""
    opts = ""
    args = ""
    cmdname = ""
    # meta_info will be removed
    meta_info = {}

    def __init__(self, config, *_args, **_kwargs):
        """ Constructor uses args as an initializer. It creates an instance
        of OptionParser, populates the options, and finally parses the 
        command line. Options are stored in the self.opts attribute.
        """
        self._config = config

    @staticmethod
    def register_options(config):
        """Registers options into a config object provided"""
        config.add_option("OUTPUT", default = 'text',
                          cache_invalidator = False,
                          help = "Output in this format (format support is module specific)")

        config.add_option("OUTPUT-FILE", default = None,
                          cache_invalidator = False,
                          help = "write output in this file")

        config.add_option("VERBOSE", default = 0, action = 'count',
                          cache_invalidator = False,
                          short_option = 'v', help = 'Verbose information')

    @classmethod
    def help(cls):
        """ This function returns a string that will be displayed when a
        user lists available plugins.
        """
        try:
            return textwrap.dedent(cls.__doc__)
        except (AttributeError, TypeError):
            return ""

    def calculate(self):
        """ This function is responsible for performing all calculations

        We should not have any output functions (e.g. print) in this
        function at all.

        If this function is expected to take a long time to return
        some data, the function should return a generator.
        """


    def execute(self):
        """ Executes the plugin command."""
        ## Executing plugins is done in two stages - first we calculate
        data = self.calculate()

        ## Then we render the result in some way based on the
        ## requested output mode:
        function_name = "render_{0}".format(self._config.OUTPUT)
        if self._config.OUTPUT_FILE:
            outfd = open(self._config.OUTPUT_FILE, 'w')
            # TODO: We should probably check that this won't blat over an existing file 
        else:
            outfd = sys.stdout

        try:
            func = getattr(self, function_name)
        except AttributeError:
            ## Try to find out what formats are supported
            result = []
            for x in dir(self):
                if x.startswith("render_"):
                    _a, b = x.split("_", 1)
                    result.append(b)

            print "Plugin {0} is unable to produce output in format {1}. Supported formats are {2}. Please send a feature request".format(self.__class__.__name__, self._config.OUTPUT, result)
            return

        func(outfd, data)


### Deprecated components
#
# This is for removal after 2.2 has been released
#

command = Command
