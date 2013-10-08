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

import sys, textwrap
import volatility.debug as debug
import volatility.fmtspec as fmtspec
import volatility.addrspace as addrspace

class Command(object):
    """ Base class for each plugin command """
    op = ""
    opts = ""
    args = ""
    cmdname = ""
    # meta_info will be removed
    meta_info = {}
    # Make these class variables so they can be modified across every plugin
    elide_data = True
    tablesep = " "

    def __init__(self, config, *_args, **_kwargs):
        """ Constructor uses args as an initializer. It creates an instance
        of OptionParser, populates the options, and finally parses the 
        command line. Options are stored in the self.opts attribute.
        """
        self._config = config
        self._formatlist = []

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

    @staticmethod
    def is_valid_profile(profile):
        return True

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

    def _formatlookup(self, profile, code):
        """Code to turn profile specific values into format specifications"""
        code = code or ""
        if not code.startswith('['):
            return code

        # Strip off the square brackets
        code = code[1:-1].lower()
        if code.startswith('addr'):
            spec = fmtspec.FormatSpec("#10x")
            if profile.metadata.get('memory_model', '32bit') == '64bit':
                spec.minwidth += 8
            if 'pad' in code:
                spec.fill = "0"
                spec.align = spec.align if spec.align else "="
            else:
                # Non-padded addresses will come out as numbers,
                # so titles should align >
                spec.align = ">"
            return spec.to_string()

        # Something went wrong
        debug.warning("Unknown table format specification: " + code)
        return ""

    def _elide(self, string, length):
        """Adds three dots in the middle of a string if it is longer than length"""
        # Only elide data if we've been asked to (which we are by default)
        if not self.elide_data:
            return string

        if length == -1:
            return string
        if len(string) < length:
            return (" " * (length - len(string))) + string
        elif len(string) == length:
            return string
        else:
            if length < 5:
                debug.error("Cannot elide a string to length less than 5")
            even = ((length + 1) % 2)
            length = (length - 3) / 2
            return string[:length + even] + "..." + string[-length:]

    def format_value(self, value, fmt):
        """ Formats an individual field using the table formatting codes"""
        profile = addrspace.BufferAddressSpace(self._config).profile
        return ("{0:" + self._formatlookup(profile, fmt) + "}").format(value)

    def table_header(self, outfd, title_format_list = None):
        """Table header renders the title row of a table

           This also stores the header types to ensure
           everything is formatted appropriately.
           It must be a list of tuples rather than a dict for ordering purposes.
        """
        titles = []
        rules = []
        self._formatlist = []
        profile = addrspace.BufferAddressSpace(self._config).profile

        for (k, v) in title_format_list:
            spec = fmtspec.FormatSpec(self._formatlookup(profile, v))
            # If spec.minwidth = -1, this field is unbounded length
            if spec.minwidth != -1:
                spec.minwidth = max(spec.minwidth, len(k))

            # Get the title specification to follow the alignment of the field
            titlespec = fmtspec.FormatSpec(formtype = 's', minwidth = max(spec.minwidth, len(k)))
            titlespec.align = spec.align if spec.align in "<>^" else "<"

            # Add this to the titles, rules, and formatspecs lists
            titles.append(("{0:" + titlespec.to_string() + "}").format(k))
            rules.append("-" * titlespec.minwidth)
            self._formatlist.append(spec)

        # Write out the titles and line rules
        if outfd:
            outfd.write(self.tablesep.join(titles) + "\n")
            outfd.write(self.tablesep.join(rules) + "\n")

    def table_row(self, outfd, *args):
        """Outputs a single row of a table"""
        reslist = []
        if len(args) > len(self._formatlist):
            debug.error("Too many values for the table")
        for index in range(len(args)):
            spec = self._formatlist[index]
            result = self._elide(("{0:" + spec.to_string() + "}").format(args[index]), spec.minwidth)
            reslist.append(result)
        outfd.write(self.tablesep.join(reslist) + "\n")
