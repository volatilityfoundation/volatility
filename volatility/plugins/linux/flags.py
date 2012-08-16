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

# flags used throughout the plugins
# these aren't going to change due to binary breakage if they would

VM_READ = 0x00000001
VM_WRITE = 0x00000002
VM_EXEC = 0x00000004

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

S_IFMT=0170000
S_IFSOCK=0140000
S_IFLNK=0120000
S_IFREG=0100000
S_IFBLK=0060000
S_IFDIR=0040000
S_IFCHR=0020000
S_IFIFO=0010000
S_ISUID=0004000
S_ISGID=0002000


