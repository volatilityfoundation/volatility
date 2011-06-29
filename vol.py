#!/usr/bin/python
#  -*- mode: python; -*-
#
# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111
import sys

if sys.version_info < (2, 6, 0):
    sys.stderr.write("Volatiltiy requires python version 2.6, please upgrade your python installation.")
    sys.exit(1)

try:
    import psyco #pylint: disable-msg=W0611,F0401
except ImportError:
    pass

import textwrap
import volatility.registry as MemoryRegistry
import volatility.conf as conf
config = conf.ConfObject()
import volatility.obj as obj
import volatility.utils as utils
import volatility.constants as constants
import volatility.debug as debug

def list_plugins():
    result = "\n\tSupported Plugin Commands:\n\n"
    keys = MemoryRegistry.PLUGIN_COMMANDS.commands.keys()
    keys.sort()
    for cmdname in keys:
        command = MemoryRegistry.PLUGIN_COMMANDS[cmdname]
        helpline = command.help() or ''
        ## Just put the title line (First non empty line) in this
        ## abbreviated display
        for line in helpline.splitlines():
            if line:
                helpline = line
                break
        result += "\t\t{0:15}\t{1}\n".format(cmdname, helpline)

    return result

def command_help(command):
    result = textwrap.dedent("""
    ---------------------------------
    Module {0}
    ---------------------------------\n""".format(command.__class__.__name__))

    return result + command.help() + "\n\n"

def main():

    # Get the version information on every output from the beginning
    # Exceptionally useful for debugging/telling people what's going on
    sys.stderr.write("Volatile Systems Volatility Framework {0}\n".format(constants.VERSION))

    # Setup the debugging format
    debug.setup()
    # Load up modules in case they set config options
    MemoryRegistry.Init()
    ## Parse all the options now
    config.parse_options(False)
    # Reset the logging level now we know whether debug is set or not
    debug.setup(config.DEBUG)

    module = None
    ## Try to find the first thing that looks like a module name
    for m in config.args:
        if m in MemoryRegistry.PLUGIN_COMMANDS.commands:
            module = m
            break

    if not module:
        config.parse_options()
        debug.error("You must specify something to do (try -h)")

    if module not in MemoryRegistry.PLUGIN_COMMANDS.commands:
        config.parse_options()
        debug.error("Invalid module [{0}].".format(module))


    try:
        if module in MemoryRegistry.PLUGIN_COMMANDS.commands:
            command = MemoryRegistry.PLUGIN_COMMANDS[module](config)

            ## Register the help cb from the command itself
            config.set_help_hook(obj.Curry(command_help, command))
            config.parse_options()

            if not config.LOCATION:
                debug.error("Please specify a location (-l) or filename (-f)")

            command.execute()
    except utils.VolatilityException, e:
        print e

if __name__ == "__main__":
    config.set_usage(usage = "Volatility - A memory forensics analysis platform.")
    config.add_help_hook(list_plugins)

    try:
        main()
    except Exception, ex:
        if config.DEBUG:
            debug.post_mortem()
        else:
            raise
    except KeyboardInterrupt:
        print "Interrupted"
