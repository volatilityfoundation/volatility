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

# flags used throughout the plugins
# these aren't going to change due to binary breakage if they would

# Protocol strings should use volatility.protos

tcp_states = ("",
              "ESTABLISHED",
              "SYN_SENT",
              "SYN_RECV",
              "FIN_WAIT1",
              "FIN_WAIT2",
              "TIME_WAIT",
              "CLOSE",
              "CLOSE_WAIT",
              "LAST_ACK",
              "LISTEN",
              "CLOSING")

MNT_NOSUID = 0x01
MNT_NODEV = 0x02
MNT_NOEXEC = 0x04
MNT_NOATIME = 0x08
MNT_NODIRATIME = 0x10
MNT_RELATIME = 0x20

mnt_flags = {
    MNT_NOSUID:     ",nosuid",
    MNT_NODEV:      ",nodev",
    MNT_NOEXEC:     ",noexec",
    MNT_NOATIME:    ",noatime",
    MNT_NODIRATIME: ",nodiratime",
    MNT_RELATIME:   ",relatime"
    }

S_IFMT = 0170000
S_IFSOCK = 0140000
S_IFLNK = 0120000
S_IFREG = 0100000
S_IFBLK = 0060000
S_IFDIR = 0040000
S_IFCHR = 0020000
S_IFIFO = 0010000
S_ISUID = 0004000
S_ISGID = 0002000


