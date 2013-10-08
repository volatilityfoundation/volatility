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

import volatility.timefmt as timefmt
import volatility.obj as obj
import volatility.utils as utils
import volatility.commands as commands

#pylint: disable-msg=C0111

class DateTime(commands.Command):
    """A simple example plugin that gets the date/time information from a Windows image"""
    def calculate(self):
        """Calculate and carry out any processing that may take time upon the image"""
        # Load the address space
        addr_space = utils.load_as(self._config)

        # Call a subfunction so that it can be used by other plugins
        return self.get_image_time(addr_space)

    def get_image_time(self, addr_space):
        """Extracts the time and date from the KUSER_SHARED_DATA area"""
        # Get the Image Datetime
        result = {}

        # Create a VOLATILITY_MAGIC object to look up the location of certain constants
        # Get the KUSER_SHARED_DATA location
        KUSER_SHARED_DATA = obj.VolMagic(addr_space).KUSER_SHARED_DATA.v()
        # Create the _KUSER_SHARED_DATA object at the appropriate offset
        k = obj.Object("_KUSER_SHARED_DATA",
                              offset = KUSER_SHARED_DATA,
                              vm = addr_space)

        # Start reading members from it
        result['ImageDatetime'] = k.SystemTime
        result['ImageTz'] = timefmt.OffsetTzInfo(-k.TimeZoneBias.as_windows_timestamp() / 10000000)

        # Return any results we got
        return result

    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        # Convert the result into a datetime object for display in local and non local format
        dt = data['ImageDatetime'].as_datetime()

        # Display the datetime in UTC as taken from the image
        outfd.write("Image date and time       : {0}\n".format(data['ImageDatetime']))
        # Display the datetime taking into account the timezone of the image itself
        outfd.write("Image local date and time : {0}\n".format(timefmt.display_datetime(dt, data['ImageTz'])))
