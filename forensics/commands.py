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


import optparse
from vutils import *

class command:
    """ Base class for each plugin command """
    op = ""
    opts = ""
    args = ""
    cmdname =""
    # meta_info will be removed
    meta_info = {}

    def __init__(self,args=None):
        """ Constructor uses args as an initializer. It creates an instance
        of OptionParser, populates the options, and finally parses the 
        command line. Options are stored in the self.opts attribute.
        """

        if args == None:
            return

        self.cmdname = self.__class__.__name__
        self.parser()
        self.opts, self.args = self.op.parse_args(args)

    def help(self):
        """ This function returns a string that will be displayed when a
        user lists available plugins.
        """
        return ""

    def calculate(self):
        """ This function is responsible for performing all calculations

        We should not have any output functions (e.g. print) in this
        function at all.

        If this function is expected to take a long time to return
        some data, the function should return a generator.
        """

    def parser(self):
        """ This method defines a parser for this plugin command. It is used
	to create an instance of OptionParser and populate its options. The
	OptionParser instances in stored in self.op. By default, it simply 
	calls the standard parser. The standard parser provides the following 
        command line options:
	  '-f', '--file', '(required) Image file'
	  '-b', '--base', '(optional) Physical offset (in hex) of DTB'
	  '-t', '--type', '(optional) Identify the image type'
        A plugin command may override this function in order to extend 
        the standard parser. 
        """

        self.op = get_standard_parser(self.cmdname)

    def execute(self):
        """ Executes the plugin command."""
        ## Executing plugins in done in two stages - first we calculate
        data = self.calculate()

        ## Then we render the result in some way based on the
        ## requested output mode:
        function_name = "render_%s" % self.opts.output
        if not self.opts.out_file:
            outfd = sys.stdout
        else:
            outfd = open(self.opts.out_file,'w')
            
        try:
            func = getattr(self, function_name)
        except AttributeError:
            print "Plugin %s is unable to produce output in format %r. Please send a bug report" % (self.__class__.__name__, self.opts.output)
            return

        func(outfd, data)