============================================================================
Volatility Framework - Volatile memory extraction utility framework
============================================================================

The Volatility Framework is a completely open collection of tools,
implemented in Python under the GNU General Public License, for the
extraction of digital artifacts from volatile memory (RAM) samples.
The extraction techniques are performed completely independent of the
system being investigated but offer visibilty into the runtime state
of the system. The framework is intended to introduce people to the
techniques and complexities associated with extracting digital artifacts
from volatile memory samples and provide a platform for further work into
this exciting area of research.

The Volatility distribution is available from: 
https://www.volatilesystems.com/default/volatility or 
http://code.google.com/p/volatility/downloads/list

Volatility should run on any platform that supports 
Python (http://www.python.org)

Volatility supports investigations of the following memory images:

Windows:
* 32-bit Windows XP Service Pack 2 and 3
* 32-bit Windows 2003 Server Service Pack 0, 1, 2
* 32-bit Windows Vista Service Pack 0, 1, 2
* 32-bit Windows 2008 Server Service Pack 1, 2 (there is no SP0)
* 32-bit Windows 7 Service Pack 0, 1
* 64-bit Windows XP Service Pack 1 and 2 (there is no SP0)
* 64-bit Windows 2003 Server Service Pack 1 and 2 (there is no SP0)
* 64-bit Windows Vista Service Pack 0, 1, 2
* 64-bit Windows 2008 Server Service Pack 1 and 2 (there is no SP0)
* 64-bit Windows 2008 R2 Server Service Pack 0 and 1
* 64-bit Windows 7 Service Pack 0 and 1

Linux: 
* 32-bit Linux kernels 2.6.11 to 3.5
* 64-bit Linux kernels 2.6.11 to 3.5
* OpenSuSE, Ubuntu, Debian, CentOS, Fedora, Mandriva, etc

Mac OSX:
* 32-bit 10.5.x Leopard (the only 64-bit 10.5 is Server, which isn't supported)
* 32-bit 10.6.x Snow Leopard
* 64-bit 10.6.x Snow Leopard
* 32-bit 10.7.x Lion
* 64-bit 10.7.x Lion
* 64-bit 10.8.x Mountain Lion (there is no 32-bit version)

Volatility does not provide memory sample acquisition
capabilities. For acquisition, there are both free and commercial
solutions available. If you would like suggestions about suitable 
acquisition solutions, please contact us at:

volatility (at) volatilesystems (dot) com

Volatility supports a variety of sample file formats and the
ability to convert between these formats:

  - Raw linear sample (dd)
  - Hibernation file
  - Crash dump file
  - VirtualBox ELF64 core dump
  - VMware saved state and snapshot files
  - EWF format (E01) 
  - LiME (Linux Memory Extractor) format
  - Firewire 
  - HPAK (FDPro)

For a more detailed list of capabilities, see the following:

    https://code.google.com/p/volatility/wiki/Release23
    https://code.google.com/p/volatility/wiki/CommandReference23
    https://code.google.com/p/volatility/wiki/CommandReferenceGui23
    https://code.google.com/p/volatility/wiki/CommandReferenceMal23
    https://code.google.com/p/volatility/wiki/CommandReferenceRegistryApi23
    https://code.google.com/p/volatility/wiki/LinuxCommandReference23
    https://code.google.com/p/volatility/wiki/MacCommandReference23

Example Data
============

If you want to give Volatility a try, you can download exemplar
data hosted by NIST at the following url:

    http://www.cfreds.nist.gov/mem/memory-images.rar

Links to other public memory images can be found at the following url:

    https://code.google.com/p/volatility/wiki/SampleMemoryImages

Mailing Lists
=============

Mailing lists to support the users and developers of Volatility
can be found at the following address:

    http://lists.volatilesystems.com/mailman/listinfo

Contact
=======
For information or requests, contact:

Volatile Systems

Web: http://www.volatilesystems.com/
     http://volatility.tumblr.com/
     
Email: volatility (at) volatilesystems (dot) com

IRC: #volatility on freenode

Twitter: @volatility 

Requirements
============
- Python 2.6 or later, but not 3.0. http://www.python.org

Some plugins may have other requirements which can be found at: 
    https://code.google.com/p/volatility/wiki/VolatilityInstallation

Quick Start
===========
1. Unpack the latest version of Volatility from
   https://www.volatilesystems.com/default/volatility or 
   http://code.google.com/p/volatility/downloads/list
   
2. To see available options, run "python vol.py -h"  

   Example:

$ python vol.py -h
Volatile Systems Volatility Framework 2.3
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=/Users/michaelligh/.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --plugins=PLUGINS     Additional plugin directories to use (colon separated)
  --info                Print information about all registered objects
  --cache-directory=/Users/michaelligh/.cache/volatility
                        Directory where cache files are stored
  --cache               Use caching
  --tz=TZ               Sets the timezone for displaying timestamps
  -f FILENAME, --filename=FILENAME
                        Filename to use when opening an image
  --profile=WinXPSP2x86
                        Name of the profile to load
  -l LOCATION, --location=LOCATION
                        A URN location from which to load an address space
  -w, --write           Enable write support
  --dtb=DTB             DTB Address
  --cache-dtb           Cache virtual to physical mappings
  --output=text         Output in this format (format support is module
                        specific)
  --output-file=OUTPUT_FILE
                        write output in this file
  -v, --verbose         Verbose information
  --shift=SHIFT         Mac KASLR shift address
  -g KDBG, --kdbg=KDBG  Specify a specific KDBG virtual address
  -k KPCR, --kpcr=KPCR  Specify a specific KPCR address

$ python vol.py --info
Volatile Systems Volatility Framework 2.3

Profiles
--------
VistaSP0x64        - A Profile for Windows Vista SP0 x64
VistaSP0x86        - A Profile for Windows Vista SP0 x86
VistaSP1x64        - A Profile for Windows Vista SP1 x64
VistaSP1x86        - A Profile for Windows Vista SP1 x86
VistaSP2x64        - A Profile for Windows Vista SP2 x64
VistaSP2x86        - A Profile for Windows Vista SP2 x86
Win2003SP0x86      - A Profile for Windows 2003 SP0 x86
Win2003SP1x64      - A Profile for Windows 2003 SP1 x64
Win2003SP1x86      - A Profile for Windows 2003 SP1 x86
Win2003SP2x64      - A Profile for Windows 2003 SP2 x64
Win2003SP2x86      - A Profile for Windows 2003 SP2 x86
Win2008R2SP0x64    - A Profile for Windows 2008 R2 SP0 x64
Win2008R2SP1x64    - A Profile for Windows 2008 R2 SP1 x64
Win2008SP1x64      - A Profile for Windows 2008 SP1 x64
Win2008SP1x86      - A Profile for Windows 2008 SP1 x86
Win2008SP2x64      - A Profile for Windows 2008 SP2 x64
Win2008SP2x86      - A Profile for Windows 2008 SP2 x86
Win7SP0x64         - A Profile for Windows 7 SP0 x64
Win7SP0x86         - A Profile for Windows 7 SP0 x86
Win7SP1x64         - A Profile for Windows 7 SP1 x64
Win7SP1x86         - A Profile for Windows 7 SP1 x86
WinXPSP1x64        - A Profile for Windows XP SP1 x64
WinXPSP2x64        - A Profile for Windows XP SP2 x64
WinXPSP2x86        - A Profile for Windows XP SP2 x86
WinXPSP3x86        - A Profile for Windows XP SP3 x86

Address Spaces
--------------
AMD64PagedMemory        - Standard AMD 64-bit address space.
ArmAddressSpace         - No docs        
FileAddressSpace        - This is a direct file AS.
HPAKAddressSpace        - This AS supports the HPAK format
IA32PagedMemory         - Standard IA-32 paging address space.
IA32PagedMemoryPae      - This class implements the IA-32 PAE paging address space. It is responsible
LimeAddressSpace        - Address space for Lime
MachOAddressSpace       - Address space for mach-o files to support atc-ny memory reader
VMWareSnapshotFile      - This AS supports VMware snapshot files
VirtualBoxCoreDumpElf64 - This AS supports VirtualBox ELF64 coredump format
WindowsCrashDumpSpace32 - This AS supports windows Crash Dump format
WindowsCrashDumpSpace64 - This AS supports windows Crash Dump format
WindowsHiberFileSpace32 - This is a hibernate address space for windows hibernation files.

Plugins
-------
apihooks                - Detect API hooks in process and kernel memory
atoms                   - Print session and window station atom tables
atomscan                - Pool scanner for _RTL_ATOM_TABLE
bioskbd                 - Reads the keyboard buffer from Real Mode memory
callbacks               - Print system-wide notification routines
clipboard               - Extract the contents of the windows clipboard
cmdscan                 - Extract command history by scanning for _COMMAND_HISTORY
connections             - Print list of open connections [Windows XP and 2003 Only]
connscan                - Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
consoles                - Extract command history by scanning for _CONSOLE_INFORMATION
crashinfo               - Dump crash-dump information
deskscan                - Poolscaner for tagDESKTOP (desktops)
devicetree              - Show device tree
dlldump                 - Dump DLLs from a process address space
dlllist                 - Print list of loaded dlls for each process
driverirp               - Driver IRP hook detection
driverscan              - Scan for driver objects _DRIVER_OBJECT
dumpcerts               - Dump RSA private and public SSL keys
dumpfiles               - Extract memory mapped and cached files
envars                  - Display process environment variables
eventhooks              - Print details on windows event hooks
evtlogs                 - Extract Windows Event Logs (XP/2003 only)
filescan                - Scan Physical memory for _FILE_OBJECT pool allocations
gahti                   - Dump the USER handle type information
gditimers               - Print installed GDI timers and callbacks
gdt                     - Display Global Descriptor Table
getservicesids          - Get the names of services in the Registry and return Calculated SID
getsids                 - Print the SIDs owning each process
handles                 - Print list of open handles for each process
hashdump                - Dumps passwords hashes (LM/NTLM) from memory
hibinfo                 - Dump hibernation file information
hivedump                - Prints out a hive
hivelist                - Print list of registry hives.
hivescan                - Scan Physical memory for _CMHIVE objects (registry hives)
hpakextract             - Extract physical memory from an HPAK file
hpakinfo                - Info on an HPAK file
idt                     - Display Interrupt Descriptor Table
iehistory               - Reconstruct Internet Explorer cache / history
imagecopy               - Copies a physical address space out as a raw DD image
imageinfo               - Identify information for the image
impscan                 - Scan for calls to imported functions
kdbgscan                - Search for and dump potential KDBG values
kpcrscan                - Search for and dump potential KPCR values
ldrmodules              - Detect unlinked DLLs
linux_arp               - Print the ARP table
linux_bash              - Recover bash history from bash process memory
linux_check_afinfo      - Verifies the operation function pointers of network protocols
linux_check_creds       - Checks if any processes are sharing credential structures
linux_check_evt_arm     - Checks the Exception Vector Table to look for syscall table hooking
linux_check_fop         - Check file operation structures for rootkit modifications
linux_check_idt         - Checks if the IDT has been altered
linux_check_modules     - Compares module list to sysfs info, if available
linux_check_syscall     - Checks if the system call table has been altered
linux_check_syscall_arm - Checks if the system call table has been altered
linux_check_tty         - Checks tty devices for hooks
linux_cpuinfo           - Prints info about each active processor
linux_dentry_cache      - Gather files from the dentry cache
linux_dmesg             - Gather dmesg buffer
linux_dump_map          - Writes selected memory mappings to disk
linux_find_file         - Recovers tmpfs filesystems from memory
linux_ifconfig          - Gathers active interfaces
linux_iomem             - Provides output similar to /proc/iomem
linux_keyboard_notifier - Parses the keyboard notifier call chain
linux_lsmod             - Gather loaded kernel modules
linux_lsof              - Lists open files
linux_memmap            - Dumps the memory map for linux tasks
linux_moddump           - Extract loaded kernel modules
linux_mount             - Gather mounted fs/devices
linux_mount_cache       - Gather mounted fs/devices from kmem_cache
linux_netstat           - Lists open sockets
linux_pidhashtable      - Enumerates processes through the PID hash table
linux_pkt_queues        - Writes per-process packet queues out to disk
linux_proc_maps         - Gathers process maps for linux
linux_psaux             - Gathers processes along with full command line and start time
linux_pslist            - Gather active tasks by walking the task_struct->task list
linux_pslist_cache      - Gather tasks from the kmem_cache
linux_pstree            - Shows the parent/child relationship between processes
linux_psxview           - Find hidden processes with various process listings
linux_route_cache       - Recovers the routing cache from memory
linux_sk_buff_cache     - Recovers packets from the sk_buff kmem_cache
linux_slabinfo          - Mimics /proc/slabinfo on a running machine
linux_tmpfs             - Recovers tmpfs filesystems from memory
linux_vma_cache         - Gather VMAs from the vm_area_struct cache
linux_volshell          - Shell in the memory image
linux_yarascan          - A shell in the Linux memory image
lsadump                 - Dump (decrypted) LSA secrets from the registry
mac_arp                 - Prints the arp table
mac_check_syscalls      - Checks to see if system call table entries are hooked
mac_check_sysctl        - Checks for unknown sysctl handlers
mac_check_trap_table    - Checks to see if mach trap table entries are hooked
mac_dead_procs          - Prints terminated/de-allocated processes
mac_dmesg               - Prints the kernel debug buffer
mac_dump_maps           - Dumps memory ranges of processes
mac_find_aslr_shift     - Find the ASLR shift value for 10.8+ images
mac_ifconfig            - Lists network interface information for all devices
mac_ip_filters          - Reports any hooked IP filters
mac_list_sessions       - Enumerates sessions
mac_list_zones          - Prints active zones
mac_lsmod               - Lists loaded kernel modules
mac_lsof                - Lists per-process opened files
mac_machine_info        - Prints machine information about the sample
mac_mount               - Prints mounted device information
mac_netstat             - Lists active per-process network connections
mac_notifiers           - Detects rootkits that add hooks into I/O Kit (e.g. LogKext)
mac_pgrp_hash_table     - Walks the process group hash table
mac_pid_hash_table      - Walks the pid hash table
mac_print_boot_cmdline  - Prints kernel boot arguments
mac_proc_maps           - Gets memory maps of processes
mac_psaux               - Prints processes with arguments in user land (**argv)
mac_pslist              - List Running Processes
mac_pstree              - Show parent/child relationship of processes
mac_psxview             - Find hidden processes with various process listings
mac_route               - Prints the routing table
mac_tasks               - List Active Tasks
mac_trustedbsd          - Lists malicious trustedbsd policies
mac_version             - Prints the Mac version
mac_volshell            - Shell in the memory image
mac_yarascan            - Scan memory for yara signatures
machoinfo               - Dump Mach-O file format information
malfind                 - Find hidden and injected code
mbrparser               - Scans for and parses potential Master Boot Records (MBRs)
memdump                 - Dump the addressable memory for a process
memmap                  - Print the memory map
messagehooks            - List desktop and thread window message hooks
mftparser               - Scans for and parses potential MFT entries
moddump                 - Dump a kernel driver to an executable file sample
modscan                 - Scan Physical memory for _LDR_DATA_TABLE_ENTRY objects
modules                 - Print list of loaded modules
mutantscan              - Scan for mutant objects _KMUTANT
netscan                 - Scan a Vista, 2008 or Windows 7 image for connections and sockets
patcher                 - Patches memory based on page scans
printkey                - Print a registry key, and its subkeys and values
privs                   - Display process privileges
procexedump             - Dump a process to an executable file sample
procmemdump             - Dump a process to an executable memory sample
pslist                  - Print all running processes by following the EPROCESS lists
psscan                  - Scan Physical memory for _EPROCESS pool allocations
pstree                  - Print process list as a tree
psxview                 - Find hidden processes with various process listings
raw2dmp                 - Converts a physical memory sample to a windbg crash dump
screenshot              - Save a pseudo-screenshot based on GDI windows
sessions                - List details on _MM_SESSION_SPACE (user logon sessions)
shellbags               - Prints ShellBags info
shimcache               - Parses the Application Compatibility Shim Cache registry key
sockets                 - Print list of open sockets
sockscan                - Scan Physical memory for _ADDRESS_OBJECT objects (tcp sockets)
ssdt                    - Display SSDT entries
strings                 - Match physical offsets to virtual addresses (may take a while, VERY verbose)
svcscan                 - Scan for Windows services
symlinkscan             - Scan for symbolic link objects
thrdscan                - Scan physical memory for _ETHREAD objects
threads                 - Investigate _ETHREAD and _KTHREADs
timeliner               - Creates a timeline from various artifacts in memory
timers                  - Print kernel timers and associated module DPCs
unloadedmodules         - Print list of unloaded modules
userassist              - Print userassist registry keys and information
userhandles             - Dump the USER handle tables
vaddump                 - Dumps out the vad sections to a file
vadinfo                 - Dump the VAD info
vadtree                 - Walk the VAD tree and display in tree format
vadwalk                 - Walk the VAD tree
vboxinfo                - Dump virtualbox information
vmwareinfo              - Dump VMware VMSS/VMSN information
volshell                - Shell in the memory image
windows                 - Print Desktop Windows (verbose details)
wintree                 - Print Z-Order Desktop Windows Tree
wndscan                 - Pool scanner for tagWINDOWSTATION (window stations)
yarascan                - Scan process or kernel memory with Yara signatures

Scanner Checks
--------------
CheckHiveSig           - Check for a registry hive signature
CheckPoolIndex         - Checks the pool index
CheckPoolSize          - Check pool block size
CheckPoolType          - Check the pool type
CheckProcess           - Check sanity of _EPROCESS
CheckSocketCreateTime  - Check that _ADDRESS_OBJECT.CreateTime makes sense
CheckThreads           - Check sanity of _ETHREAD
KPCRScannerCheck       - Checks the self referential pointers to find KPCRs
MultiPrefixFinderCheck - Checks for multiple strings per page, finishing at the offset
MultiStringFinderCheck - Checks for multiple strings per page
PoolTagCheck           - This scanner checks for the occurance of a pool tag

3. To get more information on a sample and to make sure Volatility
   supports that sample type, run 'python vol.py imageinfo -f <imagename>'

   Example:
   
    > python vol.py imageinfo -f WIN-II7VOJTUNGL-20120324-193051.raw 
    Volatile Systems Volatility Framework 2.3
    Determining profile based on KDBG search...
    
              Suggested Profile(s) : Win2008R2SP0x64, Win7SP1x64, Win7SP0x64, Win2008R2SP1x64 (Instantiated with Win7SP0x64)
                         AS Layer1 : AMD64PagedMemory (Kernel AS)
                         AS Layer2 : FileAddressSpace (/Users/Michael/Desktop/memory/WIN-II7VOJTUNGL-20120324-193051.raw)
                          PAE type : PAE
                               DTB : 0x187000L
                              KDBG : 0xf800016460a0
              Number of Processors : 1
         Image Type (Service Pack) : 1
                    KPCR for CPU 0 : 0xfffff80001647d00L
                 KUSER_SHARED_DATA : 0xfffff78000000000L
               Image date and time : 2012-03-24 19:30:53 UTC+0000
         Image local date and time : 2012-03-25 03:30:53 +0800

4. Run some other tools. -f is a required option for all tools. Some
   also require/accept other options. Run "python vol.py <cmd> -h" for
   more information on a particular command.  A Command Reference wiki
   is also available on the Google Code site:

        http://code.google.com/p/volatility/wiki/CommandReference23

   as well as Basic Usage:

        http://code.google.com/p/volatility/wiki/VolatilityUsage23

Licensing and Copyright
=======================

Copyright (C) 2007-2011 Volatile Systems

All Rights Reserved

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  
02111-1307, USA.

Bugs and Support
================
There is no support provided with Volatility. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. 

If you think you've found a bug, please report it at:

    http://code.google.com/p/volatility/issues

In order to help us solve your issues as quickly as possible,
please include the following information when filing a bug:

* The version of volatility you're using
* The operating system used to run volatility
* The version of python used to run volatility
* The suspected operating system of the memory image
* The complete command line you used to run volatility

Depending on the operating system of the memory image, you may need to provide
additional information, such as:

For Windows:
* The suspected Service Pack of the memory image

For Linux:
* The suspected kernel version of the memory image

Other options for communicaton can be found at:
    http://code.google.com/p/volatility/wiki/VolatilityIntroduction

Missing or Truncated Information
================================
Volatile Systems makes no claims about the validity or correctness of the
output of Volatility. Many factors may contribute to the
incorrectness of output from Volatility including, but not
limited to, malicious modifications to the operating system,
incomplete information due to swapping, and information corruption on
image acquisition. 

Command Reference 
====================
The following url contains a reference of all commands supported by 
Volatility.

    http://code.google.com/p/volatility/wiki/CommandReference23


