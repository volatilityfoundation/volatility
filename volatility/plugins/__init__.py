import volatility.conf as conf
import volatility.constants as constants
import os

config = conf.ConfObject()

config.add_option("PLUGINS", default = "",
                  cache_invalidator = False,
                  help = "Additional plugin directories to use (colon separated)")

# Add the PLUGINPATH, in case we're frozen
__path__ = [constants.PLUGINPATH] + [ e for e in __path__ if not constants.PLUGINPATH.startswith(e) ]

# This causes the config.PLUGINS paths to be treated as extensions of the volatility.plugins package
# Meaning that each directory is search for module when import volatility.plugins.module is requested

if config.PLUGINS:
    plugin_paths = [ os.path.abspath(x) for x in config.PLUGINS.split(":")]
    if len(plugin_paths) == 1:
        # No colons, try semi-colon to support previous syntax
        #TODO: Remove after volatility 2.3
        plugin_paths = [ os.path.abspath(x) for x in config.PLUGINS.split(";")]
    __path__.extend(plugin_paths)
