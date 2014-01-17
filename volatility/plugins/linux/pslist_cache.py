# Volatility
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

"""
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.plugins.linux.common as linux_common
from volatility.plugins.linux.slab_info import linux_slabinfo
import volatility.plugins.linux.pslist as linux_pslist

class linux_pslist_cache(linux_pslist.linux_pslist):
    """Gather tasks from the kmem_cache"""

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('UNALLOCATED', short_option = 'u',
                        default = False,
                        help = 'Show unallocated',
                        action = 'store_true')

    def calculate(self):
        linux_common.set_plugin_members(self)
        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]

        cache = linux_slabinfo(self._config).get_kmem_cache("task_struct", self._config.UNALLOCATED)

        for task in cache:
            if not pidlist or task.pid in pidlist:
                yield task

