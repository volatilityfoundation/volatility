# Volatility
# Copyright (C) 2007-2015 Volatility Foundation
# Copyright (c) 2015 Michael Ligh <michael.ligh@mnin.org>
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

import struct
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.debug as debug
import volatility.plugins.malware.svcscan as svcscan
import volatility.win32.rawreg as rawreg
import volatility.plugins.registry.hivelist as hivelist

class ServiceDiff(svcscan.SvcScan):
    "List Windows services (ala Plugx)"

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('memory_model', '32bit') == '32bit')

    @staticmethod
    def services_from_registry(addr_space):
        """Enumerate services from the cached registry hive"""

        services = {}
        plugin = hivelist.HiveList(addr_space.get_config())
        for hive in plugin.calculate():

            ## find the SYSTEM hive 
            name = hive.get_name()
            if not name.lower().endswith("system"):
                continue 
        
            ## get the root key 
            hive_space = hive.address_space() 
            root = rawreg.get_root(hive_space)

            if not root:
                break 

            ## open the services key 
            key = rawreg.open_key(root, ["ControlSet001", "Services"])
            if not key:
                break 

            ## build a dictionary of the key names 
            for subkey in rawreg.subkeys(key):
                services[(str(subkey.Name).lower())] = subkey

            ## we don't need to keep trying 
            break

        return services

    @staticmethod
    def services_from_memory_list(addr_space):
        """Enumerate services from walking the SCM's linked list"""

        services = {}
        pre_vista = addr_space.profile.metadata.get('major', 0) < 6
        mem_model = addr_space.profile.metadata.get('memory_model', '32bit') 

        if mem_model != "32bit":
            return {}

        ## find the service control manager process 
        for process in tasks.pslist(addr_space):
            if str(process.ImageFileName) != "services.exe":
                continue 

            ## create a DOS header at the process' image base address
            process_space = process.get_process_address_space()
            image_base = process.Peb.ImageBaseAddress
            dos_header = obj.Object("_IMAGE_DOS_HEADER", 
                                    offset = image_base, 
                                    vm = process_space)

            if not dos_header:
                debug.warning("Unable to parse DOS header")
                break

            ## the first section (.text) contains the values we need 
            try:
                sections = list(dos_header.get_nt_header().get_sections())
                text_seg = sections[0]
            except ValueError:
                ## couldn't parse the PE header 
                debug.warning("Could not parse the PE header")
                break 
            except IndexError:
                ## no sections were found in the array 
                debug.warning("No sections were found in the array")
                break 

            ## acquire the text section's data 
            virtual_address = text_seg.VirtualAddress + image_base
            data = process_space.zread(virtual_address, text_seg.Misc.VirtualSize)
            list_head = None

            ## look for the ScInitDatabase signature 
            for offset in utils.iterfind(data, "\xA3"):

                if not (data[offset + 5] == "\xA3" and 
                            data[offset + 10] == "\xA3" and 
                            data[offset + 15] == "\xA3" and 
                            data[offset + 20] == "\xA3" and 
                            data[offset + 25] == "\xE8"): 
                        continue

                ## the beginning of the service database list 
                list_head = obj.Object("unsigned long", 
                                offset = virtual_address + offset + 21, 
                                vm = process_space)

            ## unable to find the signature...means list walking won't work 
            if not list_head:
                debug.warning("Unable to find the signature")
                break

            record = obj.Object("_SERVICE_RECORD", 
                                offset = list_head, 
                                vm = process_space)

            while record:
                name = str(record.ServiceName.dereference() or '')
                name = name.lower()
                services[name] = record
                record = record.ServiceList.Flink.dereference()

        return services

    @staticmethod
    def compare(reg_list, mem_list):
        """Compare the services found in the registry with those in memory"""

        ## the names of all services in only the registry list 
        missing = set(reg_list.keys()) - set(mem_list.keys())

        for service in missing:
            ## the SCM only loads services with an ImagePath value so make 
            ## sure to skip those entries, as they will not end up in memory 
            has_imagepath = False
            for value in rawreg.values(reg_list[service]):
                if str(value.Name) == "ImagePath":
                    has_imagepath = True
                    break 

            if has_imagepath:
                yield reg_list[service] 

    def calculate(self):
        addr_space = utils.load_as(self._config)

        from_memory = ServiceDiff.services_from_memory_list(addr_space)
        if not from_memory:
            debug.error("Could not enumerate services from memory")

        from_registry = ServiceDiff.services_from_registry(addr_space)
        if not from_registry:
            debug.error("Could not enumerate services from the registry")

        return ServiceDiff.compare(from_registry, from_memory)

    def render_text(self, outfd, data):
        for subkey in data:
            outfd.write("\n{0:<20}: {1}\n".format("Missing service", subkey.Name))
            for value in rawreg.values(subkey):
                value_type, value_data = rawreg.value_data(value)
                outfd.write("{0:<20}: ({1}) {2}\n".format(value.Name, value_type, value_data))
