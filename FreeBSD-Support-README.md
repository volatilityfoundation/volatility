# FreeBSD Support

Author: Antoine Brodin from [SEKOIA](https://www.sekoia.fr/)

## Previous work

[Creating Volatility Support for FreeBSD](https://scholarworks.uno.edu/td/2033/) was published in 2015, however the code was never released.

## Acquiring a memory image

If the target system is a virtual machine, it's possible to take a snapshot and acquire the VM memory.

If the target system is bare metal and crashed, a legacy memory dump can be done (sysctl debug.minidump=0 ; call doadump in ddb).

If the target system is bare metal and running, a [tool](tools/freebsd/dumpmem) was developped to acquire a memory image in the lime format.

```console
# ./dumpmem FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime
Dumping 0x0 -> 0x9fbff
Dumping 0x100000 -> 0x3ffeffff
```

## Creating a volatility profile

### Prerequisites

On a system with the same kernel as the target system, kernel sources, dwarfdump and zip must be installed.

### Profile creation

```console
% cd tools/freebsd
% make
```

This will create a zip file that can be put in the `volatility/plugins/overlays/freebsd` directory.

## Plugins

### freebsd\_version

This is the first plugin I wrote, just to verify I could retrieve a string from memory.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_version
Volatility Foundation Volatility Framework 2.6.1
Version
FreeBSD 12.1-PRERELEASE r352266 GENERIC
```

### freebsd\_ifconfig

This plugin retrieves network interfaces, along with IP and IPv6 addresses.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_ifconfig
Volatility Foundation Volatility Framework 2.6.1
Driver name Interface name Addresses
em          em0            10.0.2.15
lo          lo0            ::1 fe80:2::1 127.0.0.1
```

### freebsd\_lskld

This plugin displays status of dynamic kernel linker.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_lskld
Volatility Foundation Volatility Framework 2.6.1
Id Refs Address            Size     Name
 1   17 0xffffffff80200000 38046600 /boot/kernel/kernel
 2    1 0xffffffff82649000  3840616 /boot/kernel/zfs.ko
 3    2 0xffffffff829f3000    42424 /boot/kernel/opensolaris.ko
 4    1 0xffffffff82c19000     9832 /boot/kernel/intpm.ko
 5    1 0xffffffff82c1c000     2896 /boot/kernel/smbus.ko
 6    1 0xffffffff82c1d000     2767 /boot/kernel/mac_ntpd.ko
```

### freebsd\_lsmod

This plugin displays kernel modules.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_lsmod
Volatility Foundation Volatility Framework 2.6.1
Id  Name                      Kld
  1 opensolaris               /boot/kernel/opensolaris.ko
  2 zfsctrl                   /boot/kernel/zfs.ko
  3 zfs                       /boot/kernel/zfs.ko
  4 zfs_zvol                  /boot/kernel/zfs.ko
  5 zfs_vdev                  /boot/kernel/zfs.ko
  6 xpt                       /boot/kernel/kernel
  7 cam                       /boot/kernel/kernel
  8 aprobe                    /boot/kernel/kernel
  9 pmp                       /boot/kernel/kernel
 10 nda                       /boot/kernel/kernel
...
```

### freebsd\_lsof

This plugin lists processes and open files.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_lsof
Volatility Foundation Volatility Framework 2.6.1
Pid Name     File number File type      Vnode type Socket type    Address family Protocol Path                               Device
779 dumpmem            0 DTYPE_VNODE    VCHR                                                                                 ttyv0
779 dumpmem            1 DTYPE_VNODE    VCHR                                                                                 ttyv0
779 dumpmem            2 DTYPE_VNODE    VCHR                                                                                 ttyv0
779 dumpmem            3 DTYPE_VNODE    VREG
779 dumpmem            4 DTYPE_VNODE    VCHR                                                                                 mem
772 systat             0 DTYPE_VNODE    VCHR                                                                                 ttyv2
772 systat             1 DTYPE_VNODE    VCHR                                                                                 ttyv2
772 systat             2 DTYPE_VNODE    VCHR                                                                                 ttyv2
772 systat             3 DTYPE_VNODE    VCHR                                                                                 null
772 systat             4 DTYPE_VNODE    VCHR                                                                                 null
768 tcsh              15 DTYPE_VNODE    VCHR                                                                                 ttyv2
768 tcsh              16 DTYPE_VNODE    VCHR                                                                                 ttyv2
768 tcsh              17 DTYPE_VNODE    VCHR                                                                                 ttyv2
768 tcsh              18 DTYPE_VNODE    VCHR                                                                                 ttyv2
768 tcsh              19 DTYPE_VNODE    VCHR                                                                                 ttyv2
767 top                0 DTYPE_VNODE    VCHR                                                                                 ttyv1
767 top                1 DTYPE_VNODE    VCHR                                                                                 ttyv1
767 top                2 DTYPE_VNODE    VCHR                                                                                 ttyv1
767 top                3 DTYPE_VNODE    VCHR                                                                                 null
767 top                4 DTYPE_VNODE    VCHR                                                                                 null
763 tcsh              15 DTYPE_VNODE    VCHR                                                                                 ttyv1
763 tcsh              16 DTYPE_VNODE    VCHR                                                                                 ttyv1
763 tcsh              17 DTYPE_VNODE    VCHR                                                                                 ttyv1
763 tcsh              18 DTYPE_VNODE    VCHR                                                                                 ttyv1
763 tcsh              19 DTYPE_VNODE    VCHR                                                                                 ttyv1
760 csh               15 DTYPE_VNODE    VCHR                                                                                 ttyv0
760 csh               16 DTYPE_VNODE    VCHR                                                                                 ttyv0
760 csh               17 DTYPE_VNODE    VCHR                                                                                 ttyv0
760 csh               18 DTYPE_VNODE    VCHR                                                                                 ttyv0
760 csh               19 DTYPE_VNODE    VCHR                                                                                 ttyv0
759 getty              0 DTYPE_VNODE    VCHR                                                                                 ttyv7
759 getty              1 DTYPE_VNODE    VCHR                                                                                 ttyv7
759 getty              2 DTYPE_VNODE    VCHR                                                                                 ttyv7
758 getty              0 DTYPE_VNODE    VCHR                                                                                 ttyv6
758 getty              1 DTYPE_VNODE    VCHR                                                                                 ttyv6
758 getty              2 DTYPE_VNODE    VCHR                                                                                 ttyv6
757 getty              0 DTYPE_VNODE    VCHR                                                                                 ttyv5
757 getty              1 DTYPE_VNODE    VCHR                                                                                 ttyv5
757 getty              2 DTYPE_VNODE    VCHR                                                                                 ttyv5
756 getty              0 DTYPE_VNODE    VCHR                                                                                 ttyv4
756 getty              1 DTYPE_VNODE    VCHR                                                                                 ttyv4
756 getty              2 DTYPE_VNODE    VCHR                                                                                 ttyv4
755 getty              0 DTYPE_VNODE    VCHR                                                                                 ttyv3
755 getty              1 DTYPE_VNODE    VCHR                                                                                 ttyv3
755 getty              2 DTYPE_VNODE    VCHR                                                                                 ttyv3
754 login              0 DTYPE_VNODE    VCHR                                                                                 ttyv2
754 login              1 DTYPE_VNODE    VCHR                                                                                 ttyv2
754 login              2 DTYPE_VNODE    VCHR                                                                                 ttyv2
754 login              3 DTYPE_SOCKET              SOCK_DGRAM     AF_UNIX
753 login              0 DTYPE_VNODE    VCHR                                                                                 ttyv1
753 login              1 DTYPE_VNODE    VCHR                                                                                 ttyv1
753 login              2 DTYPE_VNODE    VCHR                                                                                 ttyv1
753 login              3 DTYPE_SOCKET              SOCK_DGRAM     AF_UNIX
752 login              0 DTYPE_VNODE    VCHR                                                                                 ttyv0
752 login              1 DTYPE_VNODE    VCHR                                                                                 ttyv0
752 login              2 DTYPE_VNODE    VCHR                                                                                 ttyv0
752 login              3 DTYPE_SOCKET              SOCK_DGRAM     AF_UNIX
702 cron               0 DTYPE_VNODE    VCHR                                                                                 null
702 cron               1 DTYPE_VNODE    VCHR                                                                                 null
702 cron               2 DTYPE_VNODE    VCHR                                                                                 null
702 cron               3 DTYPE_VNODE    VDIR                                              /var/run
702 cron               4 DTYPE_VNODE    VREG                                              /var/run/cron.pid
698 sendmail           0 DTYPE_VNODE    VCHR                                                                                 null
698 sendmail           1 DTYPE_VNODE    VCHR                                                                                 null
698 sendmail           2 DTYPE_VNODE    VCHR                                                                                 null
698 sendmail           3 DTYPE_SOCKET              SOCK_DGRAM     AF_UNIX
698 sendmail           4 DTYPE_VNODE    VREG
695 sendmail           0 DTYPE_VNODE    VCHR                                                                                 null
695 sendmail           1 DTYPE_VNODE    VCHR                                                                                 null
695 sendmail           2 DTYPE_VNODE    VCHR                                                                                 null
695 sendmail           3 DTYPE_SOCKET              SOCK_STREAM    AF_INET        TCP
...
```

### freebsd\_mount

This plugin lists currently mounted file systems.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_mount
Volatility Foundation Volatility Framework 2.6.1
Special device     Mount point Type
zroot/ROOT/default /           zfs
devfs              /dev        devfs
zroot/tmp          /tmp        zfs
zroot              /zroot      zfs
zroot/usr/home     /usr/home   zfs
zroot/usr/ports    /usr/ports  zfs
zroot/usr/src      /usr/src    zfs
zroot/var/audit    /var/audit  zfs
zroot/var/log      /var/log    zfs
zroot/var/crash    /var/crash  zfs
zroot/var/mail     /var/mail   zfs
zroot/var/tmp      /var/tmp    zfs
```

### freebsd\_proc\_maps

This plugin displays processes and virtual memory mappings.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_proc_maps
Volatility Foundation Volatility Framework 2.6.1
Pid Name     Start          End            Perms Type         Path
779 dumpmem        0x200000       0x21d000 r--   OBJT_VNODE   /usr/home/freebsd/freebsd/dumpmem/dumpmem
779 dumpmem        0x21d000       0x28e000 r-x   OBJT_VNODE   /usr/home/freebsd/freebsd/dumpmem/dumpmem
779 dumpmem        0x28e000       0x293000 rw-   OBJT_VNODE   /usr/home/freebsd/freebsd/dumpmem/dumpmem
779 dumpmem        0x293000       0x4ae000 rw-   OBJT_DEFAULT
779 dumpmem     0x80028e000    0x8003b0000 rw-   OBJT_DEFAULT
779 dumpmem     0x800400000    0x800a00000 rw-   OBJT_DEFAULT
779 dumpmem  0x7fffdffff000 0x7ffffffdf000 ---   NONE
779 dumpmem  0x7ffffffdf000 0x7ffffffff000 rw-   OBJT_DEFAULT
779 dumpmem  0x7ffffffff000 0x800000000000 r-x   OBJT_PHYS
772 systat         0x200000       0x207000 r--   OBJT_VNODE   /usr/bin/systat
772 systat         0x207000       0x218000 r-x   OBJT_VNODE   /usr/bin/systat
772 systat         0x218000       0x219000 rw-   OBJT_VNODE   /usr/bin/systat
772 systat         0x219000       0x21a000 r--   OBJT_DEFAULT
772 systat         0x21a000       0x235000 rw-   OBJT_DEFAULT
772 systat      0x800218000    0x800221000 r--   OBJT_VNODE   /libexec/ld-elf.so.1
772 systat      0x800221000    0x80023b000 r-x   OBJT_VNODE   /libexec/ld-elf.so.1
772 systat      0x80023b000    0x80023c000 rw-   OBJT_VNODE   /libexec/ld-elf.so.1
772 systat      0x80023c000    0x80025f000 rw-   OBJT_DEFAULT
772 systat      0x80025f000    0x800288000 r--   OBJT_VNODE   /lib/libncursesw.so.8
772 systat      0x800288000    0x8002ba000 r-x   OBJT_VNODE   /lib/libncursesw.so.8
772 systat      0x8002ba000    0x8002bb000 rw-   OBJT_VNODE   /lib/libncursesw.so.8
...
```

### freebsd\_psaux

This plugin lists processes, executable path and arguments.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_psaux
Volatility Foundation Volatility Framework 2.6.1
Pid Name             Pathname                                  Arguments
779 dumpmem          /usr/home/freebsd/freebsd/dumpmem/dumpmem ./dumpmem FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime
772 systat           /usr/bin/systat                           systat -if
768 tcsh             /bin/tcsh                                 -tcsh
767 top              /usr/bin/top                              top
763 tcsh             /bin/tcsh                                 -tcsh
760 csh              /bin/tcsh                                 -csh
759 getty            /usr/libexec/getty                        /usr/libexec/getty Pc ttyv7
758 getty            /usr/libexec/getty                        /usr/libexec/getty Pc ttyv6
757 getty            /usr/libexec/getty                        /usr/libexec/getty Pc ttyv5
756 getty            /usr/libexec/getty                        /usr/libexec/getty Pc ttyv4
755 getty            /usr/libexec/getty                        /usr/libexec/getty Pc ttyv3
754 login            /usr/bin/login                            login [pam]
753 login            /usr/bin/login                            login [pam]
752 login            /usr/bin/login                            login [pam]
702 cron             /usr/sbin/cron                            /usr/sbin/cron -s
698 sendmail         /usr/libexec/sendmail/sendmail            sendmail: Queue runner@00:30:00 for /var/spool/clientmqueue
695 sendmail         /usr/libexec/sendmail/sendmail            sendmail: accepting connections
692 sshd             /usr/sbin/sshd                            /usr/sbin/sshd
662 ntpd             /usr/sbin/ntpd                            /usr/sbin/ntpd -p /var/db/ntp/ntpd.pid -c /etc/ntp.conf -f /var/db/ntp/ntpd.drift
489 syslogd          /usr/sbin/syslogd                         /usr/sbin/syslogd -ss
418 devd             /sbin/devd                                /sbin/devd
417 dhclient         /sbin/dhclient                            dhclient: em0
372 dhclient         /sbin/dhclient                            dhclient: em0 [priv]
369 dhclient         /sbin/dhclient                            dhclient: system.syslog
...
```

### freebsd\_pscred

This plugin lists processes and credentials (user identification, group identification...).

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_pscred
Volatility Foundation Volatility Framework 2.6.1
Pid Name             Euid Ruid Svuid Egid Rgid Svgid Umask Flags Groups
779 dumpmem             0    0     0    0    0     0 022   -     0,0,5
772 systat           1001 1001  1001 1001 1001  1001 022   -     1001,0
768 tcsh             1001 1001  1001 1001 1001  1001 022   -     1001,0
767 top              1001 1001  1001 1001 1001  1001 022   -     1001,0
763 tcsh             1001 1001  1001 1001 1001  1001 022   -     1001,0
760 csh                 0    0     0    0    0     0 022   -     0,0,5
759 getty               0    0     0    0    0     0 022   -     0
758 getty               0    0     0    0    0     0 022   -     0
757 getty               0    0     0    0    0     0 022   -     0
756 getty               0    0     0    0    0     0 022   -     0
755 getty               0    0     0    0    0     0 022   -     0
754 login               0    0     0 1001 1001  1001 022   -     1001,0
753 login               0    0     0 1001 1001  1001 022   -     1001,0
752 login               0    0     0    0    0     0 022   -     0,0,5
702 cron                0    0     0    0    0     0 022   -     0
698 sendmail           25   25    25   25   25    25 022   -     25
695 sendmail            0    0     0   25    0    25 022   -     25
692 sshd                0    0     0    0    0     0 022   -     0
662 ntpd              123  123   123  123  123   123 022   -     123
489 syslogd             0    0     0    0    0     0 022   -     0
418 devd                0    0     0    0    0     0 022   -     0
417 dhclient           65   65    65   65   65    65 022   C     65
372 dhclient            0    0     0    0    0     0 022   -     0
369 dhclient            0    0     0    0    0     0 022   -     0
...
```

### freebsd\_psenv

This plugin lists processes and environment variables.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_psenv
Volatility Foundation Volatility Framework 2.6.1
Pid Name             Environment
779 dumpmem          USER=root LOGNAME=root HOME=/root SHELL=/bin/csh BLOCKSIZE=K MAIL=/var/mail/root PATH=/s... SHLVL=1 PWD=/home/freebsd/freebsd/dumpmem GROUP=wheel HOST=freebsd EDITOR=vi PAGER=less
772 systat           USER=freebsd LOGNAME=freebsd HOME=/home/freebsd SHELL=/bin/tcsh BLOCKSIZE=K MAIL=/var/ma...ACHTYPE=x86_64 SHLVL=1 PWD=/home/freebsd GROUP=freebsd HOST=freebsd EDITOR=vi PAGER=less
768 tcsh             USER=freebsd LOGNAME=freebsd HOME=/home/freebsd SHELL=/bin/tcsh BLOCKSIZE=K MAIL=/var/ma...sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/home/freebsd/bin TERM=xterm
767 top              USER=freebsd LOGNAME=freebsd HOME=/home/freebsd SHELL=/bin/tcsh BLOCKSIZE=K MAIL=/var/ma...ACHTYPE=x86_64 SHLVL=1 PWD=/home/freebsd GROUP=freebsd HOST=freebsd EDITOR=vi PAGER=less
763 tcsh             USER=freebsd LOGNAME=freebsd HOME=/home/freebsd SHELL=/bin/tcsh BLOCKSIZE=K MAIL=/var/ma...sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/home/freebsd/bin TERM=xterm
760 csh              USER=root LOGNAME=root HOME=/root SHELL=/bin/csh BLOCKSIZE=K MAIL=/var/mail/root PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/root/bin TERM=xterm
759 getty            TERM=xterm
758 getty            TERM=xterm
757 getty            TERM=xterm
756 getty            TERM=xterm
755 getty            TERM=xterm
...
```

### freebsd\_pslist

This plugin lists processes.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_pslist
Volatility Foundation Volatility Framework 2.6.1
Offset (V)         Pid Name
0xfffff800035e9530 779 dumpmem
0xfffff80025e13000 772 systat
0xfffff80025e13530 768 tcsh
0xfffff80025e13a60 767 top
0xfffff8002545e000 763 tcsh
0xfffff8002545ea60 760 csh
0xfffff80003fb7a60 759 getty
0xfffff800035e9a60 758 getty
0xfffff800035e9000 757 getty
0xfffff80003fb7530 756 getty
0xfffff80003fb7000 755 getty
...
```

### freebsd\_yarascan

This plugin is modeled after the `linux_yarascan` and `mac_yarascan` plugins. It scans memory for yara signatures.

```console
% python2.7 vol.py -f ../FreeBSD-12.1-PRERELEASE-GENERIC-amd64.lime --profile FreeBSD-12_1-PRERELEASE-GENERIC-amd64 freebsd_yarascan -A -Y "usr/src/sys/kern/subr_capability" -s 32
Volatility Foundation Volatility Framework 2.6.1
[kernel] rule r1 addr 0xf8001cc8eb6e
0x0000f8001cc8eb6e  75 73 72 2f 73 72 63 2f 73 79 73 2f 6b 65 72 6e   usr/src/sys/kern
0x0000f8001cc8eb7e  2f 73 75 62 72 5f 63 61 70 61 62 69 6c 69 74 79   /subr_capability
[kernel] rule r1 addr 0xf8001da7ea33
0x0000f8001da7ea33  75 73 72 2f 73 72 63 2f 73 79 73 2f 6b 65 72 6e   usr/src/sys/kern
0x0000f8001da7ea43  2f 73 75 62 72 5f 63 61 70 61 62 69 6c 69 74 79   /subr_capability
Proc: systat pid 772 rule r1 addr 0x800368b6e
0x0000000800368b6e  75 73 72 2f 73 72 63 2f 73 79 73 2f 6b 65 72 6e   usr/src/sys/kern
0x0000000800368b7e  2f 73 75 62 72 5f 63 61 70 61 62 69 6c 69 74 79   /subr_capability
Proc: tcsh pid 768 rule r1 addr 0x800372b6e
0x0000000800372b6e  75 73 72 2f 73 72 63 2f 73 79 73 2f 6b 65 72 6e   usr/src/sys/kern
0x0000000800372b7e  2f 73 75 62 72 5f 63 61 70 61 62 69 6c 69 74 79   /subr_capability
Proc: top pid 767 rule r1 addr 0x800368b6e
0x0000000800368b6e  75 73 72 2f 73 72 63 2f 73 79 73 2f 6b 65 72 6e   usr/src/sys/kern
0x0000000800368b7e  2f 73 75 62 72 5f 63 61 70 61 62 69 6c 69 74 79   /subr_capability
Proc: tcsh pid 763 rule r1 addr 0x800372b6e
0x0000000800372b6e  75 73 72 2f 73 72 63 2f 73 79 73 2f 6b 65 72 6e   usr/src/sys/kern
0x0000000800372b7e  2f 73 75 62 72 5f 63 61 70 61 62 69 6c 69 74 79   /subr_capability
Proc: csh pid 760 rule r1 addr 0x800372b6e
0x0000000800372b6e  75 73 72 2f 73 72 63 2f 73 79 73 2f 6b 65 72 6e   usr/src/sys/kern
0x0000000800372b7e  2f 73 75 62 72 5f 63 61 70 61 62 69 6c 69 74 79   /subr_capability
Proc: getty pid 759 rule r1 addr 0x8002a9b6e
0x00000008002a9b6e  75 73 72 2f 73 72 63 2f 73 79 73 2f 6b 65 72 6e   usr/src/sys/kern
0x00000008002a9b7e  2f 73 75 62 72 5f 63 61 70 61 62 69 6c 69 74 79   /subr_capability
...
```

