# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import os, time, calendar
import datetime
import volatility.conf as conf
import volatility.debug as debug
try:
    import pytz
    tz_pytz = True
except ImportError:
    tz_pytz = False
config = conf.ConfObject()

class OffsetTzInfo(datetime.tzinfo):
    """Timezone implementation that allows offsets specified in seconds"""

    def __init__(self, offset = None, *args, **kwargs):
        """Accepts offset in seconds"""
        self.offset = offset
        datetime.tzinfo.__init__(self, *args, **kwargs)

    def set_offset(self, offset):
        """Simple setter for offset"""
        self.offset = offset

    def utcoffset(self, dt):
        """Returns the offset from UTC"""
        if self.offset is None:
            return None
        return datetime.timedelta(seconds = self.offset) + self.dst(dt)

    def dst(self, _dt):
        """We almost certainly can't know about DST, so we say it's always off"""
        # FIXME: Maybe we can know or make guesses about DST? 
        return datetime.timedelta(0)

    def tzname(self, _dt):
        """Return a useful timezone name"""
        if self.offset is None:
            return "UNKNOWN"

        return ""

class UTC(datetime.tzinfo):
    """Concrete instance of the UTC timezone"""

    def utcoffset(self, _dt):
        """Returns an offset from UTC of 0"""
        return datetime.timedelta(0)

    def dst(self, _dt):
        """Returns no daylight savings offset"""
        return datetime.timedelta(0)

    def tzname(self, _dt):
        """Returns the timezone name"""
        return "UTC"

def display_datetime(dt, custom_tz = None):
    """Returns a string from a datetime according to the display TZ (or a custom one"""
    timeformat = "%Y-%m-%d %H:%M:%S %Z%z"
    if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None:
        if custom_tz is not None:
            dt = dt.astimezone(custom_tz)
        elif config.TZ is not None:
            if isinstance(config.TZ, str):
                secs = calendar.timegm(dt.timetuple())
                os.environ['TZ'] = config.TZ
                time.tzset()
                # Remove the %z which appears not to work
                timeformat = timeformat[:-2]
                return time.strftime(timeformat, time.localtime(secs))
            else:
                dt = dt.astimezone(config.tz)
    return ("{0:" + timeformat + "}").format(dt)

def tz_from_string(_option, _opt_str, value, parser):
    """Stores a tzinfo object from a string"""
    if value is not None:
        if value[0] in ['+', '-']:
            # Handed a numeric offset, create an OffsetTzInfo
            valarray = [value[i:i + 2] for i in range(1, len(value), 2)]
            multipliers = [3600, 60]
            offset = 0
            for i in range(min(len(valarray), len(multipliers))):
                offset += int(valarray[i]) * multipliers[i]
            if value[0] == '-':
                offset = -offset
            timezone = OffsetTzInfo(offset = offset)
        else:
            # Value is a lookup, choose pytz over time.tzset
            if tz_pytz:
                try:
                    timezone = pytz.timezone(value)
                except pytz.UnknownTimeZoneError:
                    debug.error("Unknown display timezone specified")
            else:
                if not hasattr(time, 'tzset'):
                    debug.error("This operating system doesn't support tzset, please either specify an offset (eg. +1000) or install pytz")
                timezone = value
        parser.values.tz = timezone

config.add_option("TZ", action = "callback", callback = tz_from_string,
                  cache_invalidator = False,
                  help = "Sets the timezone for displaying timestamps",
                  default = None, nargs = 1, type = str)
