# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

""" General debugging framework """
import pdb
import sys
import inspect
import logging
import volatility.conf
config = volatility.conf.ConfObject()

config.add_option("DEBUG", short_option = 'd', default = 0,
                  cache_invalidator = False,
                  action = 'count', help = "Debug volatility")

# Largest debug value used + 1
MAX_DEBUG = 3

def setup(level = 0):
    """Sets up the global logging environment"""
    formatstr = "%(levelname)-8s: %(name)-20s: %(message)s"
    logging.basicConfig(format = formatstr)
    rootlogger = logging.getLogger('')
    rootlogger.setLevel(logging.DEBUG + 1 - level)
    for i in range(1, 9):
        logging.addLevelName(logging.DEBUG - i, "DEBUG" + str(i))

def debug(msg, level = 1):
    """Logs a message at the DEBUG level"""
    log(msg, logging.DEBUG + 1 - level)

def info(msg):
    """Logs a message at the INFO level"""
    log(msg, logging.INFO)

def warning(msg):
    """Logs a message at the WARNING level"""
    log(msg, logging.WARNING)

def error(msg):
    log(msg, logging.ERROR)
    sys.exit(1)

def critical(msg):
    log(msg, logging.CRITICAL)
    sys.exit(1)

def log(msg, level):
    modname = "volatility.py"
    try:
        frm = inspect.currentframe()
        modname = "volatility.debug"
        while modname == "volatility.debug":
            frm = frm.f_back
            mod = inspect.getmodule(frm)
            modname = mod.__name__
    except AttributeError:
        pass
    finally:
        del frm
    _log(msg, modname, level)

def _log(msg, facility, loglevel):
    """Outputs a debugging message"""
    logger = logging.getLogger(facility)
    logger.log(loglevel, msg)

def b(level = 1):
    """Enters the debugger at the call point"""
    if config.DEBUG >= level:
        pdb.set_trace()

trace = b

def post_mortem(level = 1):
    """Provides a command line interface to python after an exception's occurred"""
    if config.DEBUG >= level:
        pdb.post_mortem()
