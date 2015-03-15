# Volatility
# Copyright (c) 2015 Michael Ligh (michael.ligh@mnin.org)
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

import copy, StringIO, json
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace

registry.PluginImporter()

def get_json(config, plugin_class):
   strio = StringIO.StringIO()
   plugin = plugin_class(copy.deepcopy(config))
   plugin.render_json(strio, plugin.calculate())
   return json.loads(strio.getvalue())

def get_config(profile, target_path):
   config = conf.ConfObject()
   registry.register_global_options(config, commands.Command)
   registry.register_global_options(config, addrspace.BaseAddressSpace)
   config.parse_options()
   config.PROFILE = profile
   config.LOCATION = "file://{0}".format(target_path)
   return config 