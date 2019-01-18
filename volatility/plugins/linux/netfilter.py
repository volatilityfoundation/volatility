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
@author:       Andrew Case and Gustavo Moreira
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com,gmoreira@gmail.com
@organization:
"""
import re
from collections import namedtuple
from packaging import version
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod as linux_lsmod
import volatility.plugins.linux.banner as linux_banner
import volatility.registry as registry
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class KernelProtocolDisabledException(Exception): pass

KERNEL_LATEST = "99"    # Just a big version number to mean "until the latest version"
KERNEL_NONE = ""        # For classes that do not need a version number,ie: Base classes.

Proto = namedtuple('Proto', ['name', 'hooks'])
PROTO_NOT_IMPLEMENTED = Proto(name="UNSPEC", hooks=())
class AbstractNetfilter(object):
    """Base Netfilter class to handle all the details of the different Netfilter implementations,
    providing also constants, helpers and common routines."""

    PROTO_HOOKS = (
        PROTO_NOT_IMPLEMENTED,
        Proto(name="INET",
              hooks=("PRE_ROUTING",
                     "LOCAL_IN",
                     "FORWARD",
                     "LOCAL_OUT",
                     "POST_ROUTING")),
        Proto(name="IPV4",
              hooks=("PRE_ROUTING",
                     "LOCAL_IN",
                     "FORWARD",
                     "LOCAL_OUT",
                     "POST_ROUTING")),
        Proto(name="ARP",
              hooks=("IN",
                     "OUT",
                     "FORWARD")),
        PROTO_NOT_IMPLEMENTED,
        Proto(name="NETDEV",
              hooks=("INGRESS",)),
        PROTO_NOT_IMPLEMENTED,
        Proto(name="BRIDGE",
              hooks=("PRE_ROUTING",
                     "LOCAL_IN",
                     "FORWARD",
                     "LOCAL_OUT",
                     "POST_ROUTING",
                     "BROUTING")),
        PROTO_NOT_IMPLEMENTED,
        PROTO_NOT_IMPLEMENTED,
        Proto(name="IPV6",
              hooks=("PRE_ROUTING",
                     "LOCAL_IN",
                     "FORWARD",
                     "LOCAL_OUT",
                     "POST_ROUTING")),
        PROTO_NOT_IMPLEMENTED,
        Proto(name="DECNET",
              hooks=("PRE_ROUTING",
                     "LOCAL_IN",
                     "FORWARD",
                     "LOCAL_OUT",
                     "POST_ROUTING",
                     "HELLO",
                     "ROUTE")),
    )
    NF_MAX_HOOKS = 8

    def __init__(self, kernel_version, volinst):
        self.volinst = volinst
        self.kernel_version = version.parse(kernel_version)
        self._set_data_sizes()
        self.modules = linux_lsmod.linux_lsmod(volinst._config).get_modules()

    def _set_data_sizes(self):
        self.ptr_size = self.volinst.addr_space.profile.get_obj_size("address")
        self.list_head_size = self.volinst.addr_space.profile.get_obj_size("list_head")

    @classmethod
    def run_all(cls, kernel_version, volinst):
        """It executes the appropriate classes for this specific kernel version. It returns an
        iterable, actually a generator, ready to be returned at the same time by calculate().
        """
        kernel_version_cur = version.parse(kernel_version)
        subclass = None
        for subclass in registry._get_subclasses(cls):
            if subclass != cls:
                kv_min = version.parse(subclass.KERNEL_MIN)
                kv_max = version.parse(subclass.KERNEL_MAX)
                if kv_min <= kernel_version_cur <= kv_max:
                    nfimp_inst = subclass(kernel_version, volinst)
                    # More than one class could be executed for an specific kernel
                    # version.
                    # Certain aspects were not implemented at the same time, and
                    # also they need a different treatment. Netfilter Ingress hooks
                    # is the best example and the main reason of this.
                    for data in cls._execute(nfimp_inst):
                        yield data

        if subclass is None:
            debug.error("Unsupported netfilter kernel implementation for %s"%(kernel_version))

    @classmethod
    def _proto_hook_loop(cls, nfimp_inst):
        """It flattens the protocol families and hooks"""
        for proto_idx, proto in enumerate(AbstractNetfilter.PROTO_HOOKS):
            if proto.name in (PROTO_NOT_IMPLEMENTED.name, "INET"):
                # There is no such Netfilter hook implementation for INET protocol in the kernel
                # AFAIU this is used like NFPROTO_INET = NFPROTO_IPV4 || NFPROTO_IPV6
                continue
            if proto.name not in nfimp_inst.subscribed_protocols():
                # This protocol is not managed in this object
                continue
            for hook_idx, hook_name in enumerate(proto.hooks):
                yield proto_idx, proto.name, len(proto.hooks), hook_idx, hook_name

    @classmethod
    def _execute(cls, nfimp_inst):
        for netns, net in nfimp_inst.get_net_namespaces():
            for proto_idx, proto_name, hooks_count, hook_idx, hook_name in cls._proto_hook_loop(nfimp_inst):
                try:
                    hooks_container = nfimp_inst.get_hooks_container_by_protocol(net, proto_name)
                except KernelProtocolDisabledException:
                    continue
                if not hooks_container:
                    continue
                for hook_container in hooks_container:
                    for hook_ops in nfimp_inst.get_hook_ops(hook_container, proto_idx, hooks_count, hook_idx):
                        if not hook_ops:
                            continue
                        hook_ops_addr = hook_ops.hook.v()
                        found, module = nfimp_inst.volinst.is_known_address_name(hook_ops_addr, nfimp_inst.modules)
                        hooked = "False" if found else "True"

                        yield netns, proto_name, hook_name, hook_ops_addr, hooked, module

    # Helpers
    def build_nf_hook_ops_array(self, nf_hook_entries):
        """Function helper to build the array of arrays of nf_hook_ops give a nf_hook_entries"""
        # nf_hook_ops array is not part of the struct nf_hook_entries definition, so we need to
        # craft it.
        nf_hook_entry_count = nf_hook_entries.num_hook_entries

        nf_hook_entries_hook_addr = nf_hook_entries.hooks.obj_offset
        nf_hook_entry_arr = obj.Object("Array",
                                       targetType="nf_hook_entry",
                                       offset=nf_hook_entries_hook_addr,
                                       count=nf_hook_entry_count,
                                       vm=self.volinst.addr_space)

        nf_hook_ops_addr = nf_hook_entries_hook_addr + nf_hook_entry_arr.size()
        nf_hook_ops_ptr_arr = obj.Object("Array",
                                         targetType="Pointer",
                                         offset=nf_hook_ops_addr,
                                         count=nf_hook_entry_count,
                                         vm=self.volinst.addr_space)

        return nf_hook_ops_ptr_arr

    # Common functions to many of the implementations
    def subscribed_protocols(self):
        """Most of the implementation handlers respond to these protocols, except the ingress hook
        implemention which handles an specific protocol called "NETDEV".
        """
        return ("IPV4", "ARP", "BRIDGE", "IPV6", "DECNET")

    def get_net_namespaces(self):
        """Common function to retrieve the different namespaces.
        From 4.3 on, all the implementations use network namespaces."""
        nslist_addr = self.volinst.addr_space.profile.get_symbol("net_namespace_list")

        nethead = obj.Object("list_head", offset=nslist_addr, vm=self.volinst.addr_space)
        for net_idx, net in enumerate(nethead.list_of_type("net", "list")):
            yield net_idx, net

    def get_hooks_container_by_protocol(self, net, proto_name):
        """Except for kernels < 4.3, all the implementations use network namespaces.
        Also the data structure which contains the hooks, even though it changes its implementation
        and/or data type, it is always in this location.
        """
        yield net.nf.hooks.obj_offset

    # Interface
    def get_hook_ops(self, nf_hooks_addr, proto_idx, hooks_count, hook_idx):
        """This is the most variable/unstable part of all Netfilter hook designs, it changes almost
        in every single implementation.
        """
        raise NotImplementedError("You must implement this method")


class NetfilterImp_to_4_2_8(AbstractNetfilter):
    """At this point, Netfilter hooks were implemented as a linked list of 'struct nf_hook_ops'
    type. One linked list per protocol per hook type. It was like that until 4.2.8.

        struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];
    """
    KERNEL_MIN = "0"
    KERNEL_MAX = "4.2.8"

    def get_net_namespaces(self):
        # In kernels <= 4.2.8 netfilter hooks are not implemented per namespaces
        netns, net = "-", None
        yield netns, net

    def get_hooks_container_by_protocol(self, net, proto_name):
        nf_hooks_addr = self.volinst.addr_space.profile.get_symbol("nf_hooks")
        if nf_hooks_addr is None:
            debug.error("Unable to analyze NetFilter. It is either disabled or compiled as a module.")
        yield nf_hooks_addr

    def get_hook_ops(self, nf_hooks_addr, proto_idx, hooks_count, hook_idx):
        # It seems the API doesn't deal with array of arrays very well.
        # So, doing it the old-school way
        arr = nf_hooks_addr + (proto_idx * (self.list_head_size * AbstractNetfilter.NF_MAX_HOOKS))
        list_head_addr = arr + (hook_idx * self.list_head_size)
        list_head = obj.Object("list_head", offset=list_head_addr, vm=self.volinst.addr_space)

        return list_head.list_of_type("nf_hook_ops", "list")


class NetfilterImp_4_3_to_4_8_17(AbstractNetfilter):
    """Netfilter hooks were added to network namepaces in 4.3.
    It is still implemented as a linked list of 'struct nf_hook_ops' type but inside a network
    namespace. One linked list per protocol per hook type.

        struct net { ... struct netns_nf nf; ... }
        struct netns_nf { ...
            struct list_head hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]; ... }
    """
    KERNEL_MIN = "4.3"
    KERNEL_MAX = "4.8.17"

    def get_hook_ops(self, nf_hooks_addr, proto_idx, hooks_count, hook_idx):
        # It seems the API doesn't deal with array of arrays very well.
        # So, doing it the old-school way
        arr = nf_hooks_addr + (proto_idx * (self.list_head_size * AbstractNetfilter.NF_MAX_HOOKS))
        list_head_addr = arr + (hook_idx * self.list_head_size)
        list_head = obj.Object("list_head", offset=list_head_addr, vm=self.volinst.addr_space)

        return list_head.list_of_type("nf_hook_ops", "list")


class NetfilterImp_4_9_to_4_13_16(AbstractNetfilter):
    """In this range of kernel versions, the doubly-linked lists of netfilter hooks were replaced
    by an array of arrays of nf_hook_entry pointers in a singly-linked lists.
        struct net { ... struct netns_nf nf; ... }
        struct netns_nf { ..
            struct nf_hook_entry __rcu *hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]; ... }

    Also in v4.10 the struct nf_hook_entry changed, a hook function pointer was added to it.
    However, for simplicity of this design, we will still take the hook address from the
    nf_hook_ops. As per v5.0-rc2, the hook address is duplicated in both sides.
    - v4.9:
        struct nf_hook_entry {
            struct nf_hook_entry      *next;
            struct nf_hook_ops        ops;
            const struct nf_hook_ops  *orig_ops; };
    - v4.10:
        struct nf_hook_entry {
            struct nf_hook_entry      *next;
            nf_hookfn                 *hook;
            void                      *priv;
            const struct nf_hook_ops  *orig_ops; };
    (*) Even though the hook address is in the struct nf_hook_entry, we use the original
    nf_hook_ops hook address value, the one which was filled by the user, to make it uniform to all
    the implementations.
    """
    KERNEL_MIN = "4.9"
    KERNEL_MAX = "4.13.16"

    def get_hook_ops(self, nf_hooks_addr, proto_idx, hooks_count, hook_idx):
        # It seems the API doesn't deal with array of arrays very well.
        # So doing it the old-school way
        arr = nf_hooks_addr + (proto_idx * (self.ptr_size * AbstractNetfilter.NF_MAX_HOOKS))
        nf_hook_entry_addr = arr + (hook_idx * self.ptr_size)
        if not nf_hook_entry_addr:
            yield None

        nf_hook_entry_ptr = obj.Object("Pointer",
                                       offset=nf_hook_entry_addr,
                                       vm=self.volinst.addr_space)

        nf_hook_entry_list = nf_hook_entry_ptr.dereference_as("nf_hook_entry")
        for nf_hook_entry in linux_common.walk_internal_list("nf_hook_entry", "next", nf_hook_entry_list):
            nf_hook_ops = nf_hook_entry.orig_ops.dereference_as("nf_hook_ops")
            yield nf_hook_ops


class NetfilterImp_4_14_to_4_15_18(AbstractNetfilter):
    """nf_hook_ops was removed from struct nf_hook_entry. Instead, it was stored adjacent in memory
    to the nf_hook_entry array, in the new struct 'nf_hook_entries'.
    However, this nf_hooks_ops array 'orig_ops' is not part of the nf_hook_entries struct
    definition. So, we have to craft it by hand.

        struct net { ... struct netns_nf nf; ... }
        struct netns_nf {
            struct nf_hook_entries *hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]; ... }
        struct nf_hook_entries {
            u16                         num_hook_entries; /* plus padding */
            struct nf_hook_entry        hooks[];
            //const struct nf_hook_ops *orig_ops[]; }
        struct nf_hook_entry {
            nf_hookfn   *hook;
            void        *priv; }

    (*) Even though the hook address is in the struct nf_hook_entry, we use the original
    nf_hook_ops hook address value, the one which was filled by the user, to make it uniform to all
    the implementations.
    """
    KERNEL_MIN = "4.14"
    KERNEL_MAX = "4.15.18"

    def get_nf_hook_entries_ptr(self, nf_hooks_addr, proto_idx, hook_idx, hooks_count):
        """This allows to support different hook array implementations from this version on.
        For instance, in kernels >= 4.16 this multi-dimensional array is split in one-dimensional
        array of pointers to nf_hooks_entries per each protocol."""
        arr = nf_hooks_addr + (proto_idx * (self.ptr_size * AbstractNetfilter.NF_MAX_HOOKS))
        nf_hook_entries_addr = arr + (hook_idx * self.ptr_size)
        nf_hook_entries_ptr = obj.Object("Pointer",
                                         offset=nf_hook_entries_addr,
                                         vm=self.volinst.addr_space)
        return nf_hook_entries_ptr

    def get_hook_ops(self, nf_hooks_addr, proto_idx, hooks_count, hook_idx):
        nf_hook_entries_ptr = self.get_nf_hook_entries_ptr(nf_hooks_addr, proto_idx, hook_idx, hooks_count)
        if not nf_hook_entries_ptr:
            yield None

        nf_hook_entries = nf_hook_entries_ptr.dereference_as("nf_hook_entries")
        nf_hook_ops_ptr_arr = self.build_nf_hook_ops_array(nf_hook_entries)
        for nf_hook_ops_ptr in nf_hook_ops_ptr_arr:
            nf_hook_ops = nf_hook_ops_ptr.dereference_as("nf_hook_ops")
            yield nf_hook_ops


class NetfilterImp_4_16_to_latest(NetfilterImp_4_14_to_4_15_18):
    """The multidimensional array of nf_hook_entries was split in a one-dimensional array per each
    protocol.

        struct net {
            struct netns_nf nf; ... }
        struct  netns_nf  {
            struct nf_hook_entries * hooks_ipv4[NF_INET_NUMHOOKS];
            struct nf_hook_entries * hooks_ipv6[NF_INET_NUMHOOKS];
            struct nf_hook_entries * hooks_arp[NF_ARP_NUMHOOKS];
            struct nf_hook_entries * hooks_bridge[NF_INET_NUMHOOKS];
            struct nf_hook_entries * hooks_decnet[NF_DN_NUMHOOKS]; ... }
        struct nf_hook_entries {
	    u16                         num_hook_entries; /* plus padding */
	    struct nf_hook_entry        hooks[];
	    //const struct nf_hook_ops *orig_ops[]; }
        struct nf_hook_entry {
            nf_hookfn   *hook;
	    void        *priv; }

    (*) Even though the hook address is in the struct nf_hook_entry, we use the original
    nf_hook_ops hook address value, the one which was filled by the user, to make it uniform to all
    the implementations.
    """
    KERNEL_MIN = "4.16"
    KERNEL_MAX = KERNEL_LATEST

    def get_hooks_container_by_protocol(self, net, proto_name):
        try:
            if proto_name == "IPV4":
                net_nf_hooks = net.nf.hooks_ipv4
            elif proto_name == "ARP":
                net_nf_hooks = net.nf.hooks_arp
            elif proto_name == "BRIDGE":
                net_nf_hooks = net.nf.hooks_bridge
            elif proto_name == "IPV6":
                net_nf_hooks = net.nf.hooks_ipv6
            elif proto_name == "DECNET":
                net_nf_hooks = net.nf.hooks_decnet
            else:
                debug.error("Weird, we didn't subscribe to this protocol %s"% (proto_name))
        except AttributeError:
            # Protocol family disabled at kernel compilation
            #  CONFIG_NETFILTER_FAMILY_ARP=n ||
            #  CONFIG_NETFILTER_FAMILY_BRIDGE=n ||
            #  CONFIG_DECNET=n
            raise KernelProtocolDisabledException()
        yield net_nf_hooks.obj_offset

    def get_nf_hook_entries_ptr(self, nf_hooks_addr, proto_idx, hook_idx, hooks_count):
        nf_hook_entries_ptr_arr = obj.Object("Array",
                                             targetType="Pointer",
                                             offset=nf_hooks_addr,
                                             count=hooks_count,
                                             vm=self.volinst.addr_space)
        nf_hook_entries_ptr = nf_hook_entries_ptr_arr[hook_idx]
        return nf_hook_entries_ptr


class AbstractNetfilterIngress(AbstractNetfilter):
    """Base class to handle the Netfilter Ingress hooks.
    It won't be executed. It has some common functions to all Netfilter Ingress hook implementions.

    Netfilter Ingress hooks are set per network device which belongs to a network namespace.
    """
    KERNEL_MIN = KERNEL_NONE
    KERNEL_MAX = KERNEL_NONE

    def subscribed_protocols(self):
        return ("NETDEV",)

    def get_hooks_container_by_protocol(self, net, proto_name):
        if proto_name != "NETDEV":
            debug.error("Weird, we didn't subscribe to this protocol %s"% (proto_name))

        for net_device in net.dev_base_head.list_of_type("net_device", "dev_list"):
            try:
                nf_hooks_ingress = net_device.nf_hooks_ingress
            except AttributeError:
                # CONFIG_NETFILTER_INGRESS=n
                raise KernelProtocolDisabledException()
            yield nf_hooks_ingress


class NetfilterIngressImp_4_2_to_4_8_17(AbstractNetfilterIngress):
    """This is the first implementation of Netfilter Ingress hooks which was implemented using a
    doubly-linked list of nf_hook_ops.
        struct list_head nf_hooks_ingress;
    """

    KERNEL_MIN = "4.2"
    KERNEL_MAX = "4.8.17"

    def get_hook_ops(self, nf_hooks_ingress, proto_idx, hooks_count, hook_idx):
        return nf_hooks_ingress.list_of_type("nf_hook_ops", "list")


class NetfilterIngressImp_4_9_to_4_13_16(AbstractNetfilterIngress):
    """In 4.9 it was changed to a simple singly-linked list.
        struct nf_hook_entry * nf_hooks_ingress;
    """
    KERNEL_MIN = "4.9"
    KERNEL_MAX = "4.13.16"

    def get_hook_ops(self, nf_hooks_ingress, proto_idx, hooks_count, hook_idx):
        if not nf_hooks_ingress:
            yield None

        nf_hook_entry_list = nf_hooks_ingress.dereference_as("nf_hook_entry")
        for nf_hook_entry in linux_common.walk_internal_list("nf_hook_entry", "next", nf_hook_entry_list):
            nf_hook_ops = nf_hook_entry.orig_ops.dereference_as("nf_hook_ops")
            yield nf_hook_ops


class NetfilterIngressImp_4_14_to_latest(AbstractNetfilterIngress):
    """In 4.14 the hook list was converted to an array of pointers inside the struct
    nf_hook_entries.
        struct nf_hook_entries * nf_hooks_ingress;
        struct nf_hook_entries {
            u16 num_hook_entries; // padding
            struct nf_hook_entry hooks[];
        }
    """
    KERNEL_MIN = "4.14"
    KERNEL_MAX = KERNEL_LATEST

    def get_hook_ops(self, nf_hook_entries_ptr, proto_idx, hooks_count, hook_idx):
        if not nf_hook_entries_ptr:
            yield None

        nf_hook_entries = nf_hook_entries_ptr.dereference_as("nf_hook_entries")
        nf_hook_ops_ptr_arr = self.build_nf_hook_ops_array(nf_hook_entries)
        for nf_hook_ops_ptr in nf_hook_ops_ptr_arr:
            nf_hook_ops = nf_hook_ops_ptr.dereference_as("nf_hook_ops")
            yield nf_hook_ops


class linux_netfilter(linux_common.AbstractLinuxCommand):
    """Lists Netfilter hooks."""

    def _get_kernel_version(self):
        banner = linux_banner.linux_banner(self._config).calculate().next()
        match = re.match(r"^Linux version (\d+\.\d+\.\d+)", banner)
        if not match:
            debug.error("Unable to get kernel version")

        return match.group(1)

    def calculate(self):
        linux_common.set_plugin_members(self)
        kernel_version = self._get_kernel_version()
        return AbstractNetfilter.run_all(kernel_version, volinst=self)

    def unified_output(self, data):
        return TreeGrid([("NS", str),
                         ("Proto", str),
                         ("Hook", str),
                         ("Handler", Address),
                         ("IsHooked", str),
                         ("Module", str)],
                        self.generator(data))

    def generator(self, data):
        for namespace, proto_name, hook_name, hook_addr, hooked, module in data:
            yield (0, [str(namespace),
                       str(proto_name),
                       str(hook_name),
                       Address(hook_addr),
                       str(hooked),
                       str(module)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("NS", "2"),
                                  ("Proto", "10"),
                                  ("Hook", "16"),
                                  ("Handler", "[addrpad]"),
                                  ("Is Hooked", "5"),
                                  ("Module", "30")])

        for namespace, proto_name, hook_name, hook_addr, hooked, module in data:
            self.table_row(outfd, namespace, proto_name, hook_name, hook_addr, hooked, module)
