# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod as linux_lsmod

class linux_netfilter(linux_common.AbstractLinuxCommand):
    """Gather active tasks by walking the task_struct->task list"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        # struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]
        # NFPROTO_NUMPROTO = 12
        # NF_MAX_HOOKS = 7
      
        nf_hooks_addr = self.addr_space.profile.get_symbol("nf_hooks")

        # nf_hooks_outer = obj.Object(theType="Array", targetType="list_head", offset = nf_hooks_addr, vm = self.addr_space, count = 13)

        # TODO
        list_head_size = 16
        
        for outer in range(13):
            arr = nf_hooks_addr + (outer * (list_head_size * 8))
           
            for inner in range(8):
                list_head = obj.Object("list_head", offset = arr + (inner * list_head_size), vm = self.addr_space)
        
                for hook_ops in list_head.list_of_type("nf_hook_ops", "list"):
                    yield outer, inner, hook_ops.hook.v()

    def render_text(self, outfd, data):
        modules  = linux_lsmod.linux_lsmod(self._config).get_modules()
        hook_names = ["PRE_ROUTING", "LOCAL_IN", "FORWARD", "LOCAL_OUT", "POST_ROUTING"]
        proto_names = ["", "", "IPV4"]

        self.table_header(outfd, [("Proto", "5"), ("Hook", "16"), ("Handler", "[addrpad]"), ("Is Hooked", "5")])

        for outer, inner, hook_addr in data:
            if self.is_known_address(hook_addr, modules):
                hooked = "False"
            else:
                hooked = "True"

            self.table_row(outfd, proto_names[outer], hook_names[inner], hook_addr, hooked)











