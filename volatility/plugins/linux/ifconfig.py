# Volatility
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.plugins.linux.common as linux_common
import volatility.debug as debug
import volatility.obj as obj

class linux_ifconfig(linux_common.AbstractLinuxCommand):
    """Gathers active interfaces"""

    def calculate(self):
        linux_common.set_plugin_members(self)

        # newer kernels
        if self.addr_space.profile.get_symbol("net_namespace_list"):
            for (net_dev, in_dev) in self.get_devs_namespace():
                yield (net_dev, in_dev)

        elif self.addr_space.profile.get_symbol("dev_base"):
            for (net_dev, in_dev) in self.get_devs_base():
                yield (net_dev, in_dev)

        else:
            debug.error("Unable to determine ifconfig information")

    def get_devs_base(self):

        net_device_ptr = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("dev_base"), vm = self.addr_space)
        net_device = net_device_ptr.dereference_as("net_device")

        for net_dev in linux_common.walk_internal_list("net_device", "next", net_device):

            in_dev = obj.Object("in_device", offset = net_dev.ip_ptr, vm = self.addr_space)

            yield net_dev, in_dev

    def get_devs_namespace(self):

        nslist_addr = self.addr_space.profile.get_symbol("net_namespace_list")
        nethead = obj.Object("list_head", offset = nslist_addr, vm = self.addr_space)

        # walk each network namespace
        # http://www.linuxquestions.org/questions/linux-kernel-70/accessing-ip-address-from-kernel-ver-2-6-31-13-module-815578/
        for net in nethead.list_of_type("net", "list"):

            # walk each device in the current namespace
            for net_dev in net.dev_base_head.list_of_type("net_device", "dev_list"):

                in_dev = obj.Object("in_device", offset = net_dev.ip_ptr, vm = self.addr_space)

                yield net_dev, in_dev

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Interface", "16"),
                                  ("IP Address", "20"),
                                  ("MAC Address", "18"),
                                  ("Promiscous Mode", "5")])

        for net_dev, in_dev in data:

            # for interfaces w/o an ip address (dummy/bond)
            if in_dev.ifa_list:
                ip = in_dev.ifa_list.ifa_address.cast('IpAddress')
            else:
                ip = "0.0.0.0"

            if self.profile.obj_has_member("net_device", "perm_addr"):
                hwaddr = net_dev.perm_addr
            else:
                hwaddr = net_dev.dev_addr

            mac_addr = ":".join(["{0:02x}".format(x) for x in hwaddr][:6])

            self.table_row(outfd, net_dev.name, ip, mac_addr, str(net_dev.promisc))

