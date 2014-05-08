# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.mac.common as common
import volatility.plugins.mac.list_files as mac_list_files

class mac_dump_file(common.AbstractMacCommand):
    """ Dumps a specified file """

    def __init__(self, config, *args, **kwargs):
        common.AbstractMacCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('FILE-OFFSET', short_option = 'q', default = None, help = 'Virtual address of vnode structure from mac_list_files', action = 'store', type = 'int')
        self._config.add_option('OUTFILE', short_option = 'O', default = None, help = 'output file path', action = 'store', type = 'str')

    def calculate(self):
        common.set_plugin_members(self)

        outfile   = self._config.outfile
        vnode_off = self._config.FILE_OFFSET
        
        if not outfile:
            debug.error("You must specify an output file (-O/--outfile)")

        if not vnode_off:
            debug.error("You must specificy a vnode address (-q/--file-offset) from mac_list_files")

        fd = open(outfile, "wb")

        vnode = obj.Object("vnode", offset = vnode_off, vm = self.addr_space)

        moc  = vnode.v_un.vu_ubcinfo.ui_control.moc_object
        memq = moc.memq 

        cur = memq.next.dereference_as("vm_page")

        wrote = 0

        file_size = vnode.v_un.vu_ubcinfo.ui_size

        #print "file size: %d %d" % (vnode.v_un.vu_ubcinfo.ui_size, vnode.v_un.vu_ubcinfo.ui_size/4096)
        #print "pmapped: %d wire count: %d active: %d inactive: %d offset: %d" % (cur.pmapped, cur.wire_count, cur.active, cur.inactive, cur.offset)

        while cur and cur.is_valid() and cur.offset < file_size:
            #print "pmapped: %d wire count: %d active: %d inactive: %d offset: %d" % (cur.pmapped, cur.wire_count, cur.active, cur.inactive, cur.offset)
            # FIXME -- use the proper load_as call
            buf = self.addr_space.base.zread(cur.phys_page * 4096, 4096)              

            fd.seek(cur.offset.v())

            fd.write(buf) 
            
            wrote = wrote + 4096

            cur = cur.listq.next.dereference_as("vm_page")

        fd.close()

        yield vnode_off, outfile, wrote
 
    def render_text(self, outfd, data):
        for (vnode_off, outfile, wrote) in data:
            outfd.write("Wrote {0} bytes to {1} from vnode at address {2:x}\n".format(wrote, outfile, vnode_off))

