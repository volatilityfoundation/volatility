import volatility.conf as conf
import volatility.constants as constants
import os

config = conf.ConfObject()

# Add the PLUGINPATH, in case we're frozen
__path__.extend([constants.PLUGINPATH])

# This causes the config.PLUGINS paths to be treated as extensions of the volatility.plugins package
# Meaning that each directory is search for module when import volatility.plugins.module is requested

if config.PLUGINS:
    __path__.extend([ os.path.abspath(x) for x in config.PLUGINS.split(";")])
