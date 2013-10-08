# Volatility
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

class VolatilityException(Exception):
    """Generic Volatility Specific exception, to help differentiate from other exceptions"""
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class AddrSpaceError(VolatilityException):
    """Address Space Exception, so we can catch and deal with it in the main program"""
    def __init__(self):
        self.reasons = []
        VolatilityException.__init__(self, "No suitable address space mapping found")

    def append_reason(self, driver, reason):
        self.reasons.append((driver, reason))

    def __str__(self):
        result = VolatilityException.__str__(self) + "\nTried to open image as:\n" #pylint: disable-msg=E1101
        for k, v in self.reasons:
            result += " {0}: {1}\n".format(k, v)

        return result

class CacheRelativeURLException(VolatilityException):
    """Exception for gracefully not saving Relative URLs in the cache"""

class SanityCheckException(VolatilityException):
    """Exception for failed sanity checks (which can potentially be disabled)"""
