import volatility.conf as conf
import volatility.constants as constants
import os
import sys

config = conf.ConfObject()

help_prefix = ""
plugin_separator = ":"
# Make a platform-dependent decision on plugin path separators
# The separator is now in keeping with the PATH environment variable
if sys.platform.startswith('win'):
    help_prefix = "semi-"
    plugin_separator = ";"


config.add_option("PLUGINS", default = "",
                  cache_invalidator = False,
                  help = "Additional plugin directories to use (" + help_prefix + "colon separated)")

# Add the PLUGINPATH, in case we're frozen
__path__ = [constants.PLUGINPATH] + [ e for e in __path__ if not constants.PLUGINPATH.startswith(e) ]

# This causes the config.PLUGINS paths to be treated as extensions of the volatility.plugins package
# Meaning that each directory is search for module when import volatility.plugins.module is requested

if config.PLUGINS:
    plugin_paths = [ os.path.abspath(x) for x in config.PLUGINS.split(plugin_separator)]
    __path__.extend(plugin_paths)
