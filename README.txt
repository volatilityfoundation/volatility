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
http://www.volatilityfoundation.org/#!releases/component_71401

Volatility should run on any platform that supports 
Python (http://www.python.org)

Volatility supports investigations of the following memory images:

Windows:
* 32-bit Windows XP Service Pack 2 and 3
* 32-bit Windows 2003 Server Service Pack 0, 1, 2
* 32-bit Windows Vista Service Pack 0, 1, 2
* 32-bit Windows 2008 Server Service Pack 1, 2 (there is no SP0)
* 32-bit Windows 7 Service Pack 0, 1
* 32-bit Windows 8 and 8.1
* 64-bit Windows XP Service Pack 1 and 2 (there is no SP0)
* 64-bit Windows 2003 Server Service Pack 1 and 2 (there is no SP0)
* 64-bit Windows Vista Service Pack 0, 1, 2
* 64-bit Windows 2008 Server Service Pack 1 and 2 (there is no SP0)
* 64-bit Windows 2008 R2 Server Service Pack 0 and 1
* 64-bit Windows 7 Service Pack 0 and 1
* 64-bit Windows 8 and 8.1 
* 64-bit Windows Server 2012 and 2012 R2 

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
* 64-bit 10.9.x Mavericks (there is no 32-bit version)

Volatility does not provide memory sample acquisition
capabilities. For acquisition, there are both free and commercial
solutions available. If you would like suggestions about suitable 
acquisition solutions, please contact us at:

volatility (at) volatilityfoundation (dot) org

Volatility supports a variety of sample file formats and the
ability to convert between these formats:

  - Raw linear sample (dd)
  - Hibernation file
  - Crash dump file
  - VirtualBox ELF64 core dump
  - VMware saved state and snapshot files
  - EWF format (E01) 
  - LiME (Linux Memory Extractor) format
  - Mach-o file format 
  - QEMU virtual machine dumps
  - Firewire 
  - HPAK (FDPro)

For a more detailed list of capabilities, see the following:

    https://github.com/volatilityfoundation/volatility/wiki

Example Data
============

If you want to give Volatility a try, you can download exemplar
memory images from the following url:

    https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples

Mailing Lists
=============

Mailing lists to support the users and developers of Volatility
can be found at the following address:

    http://lists.volatilesystems.com/mailman/listinfo

Contact
=======
For information or requests, contact:

Volatility Foundation

Web: http://www.volatilityfoundation.org
     http://volatility-labs.blogspot.com
     http://volatility.tumblr.com
     
Email: volatility (at) volatilityfoundation (dot) org

IRC: #volatility on freenode

Twitter: @volatility 

Requirements
============
- Python 2.6 or later, but not 3.0. http://www.python.org

Some plugins may have other requirements which can be found at: 
    https://github.com/volatilityfoundation/volatility/wiki/Installation

Quick Start
===========
1. Unpack the latest version of Volatility from
    volatilityfoundation.org
   
2. To see available options, run "python vol.py -h" or "python vol.py --info"

   Example:

$ python vol.py --info
Volatility Foundation Volatility Framework 2.4
Usage: Volatility - A memory forensics analysis platform.

Profiles
--------
VistaSP0x64                - A Profile for Windows Vista SP0 x64
VistaSP0x86                - A Profile for Windows Vista SP0 x86
VistaSP1x64                - A Profile for Windows Vista SP1 x64
VistaSP1x86                - A Profile for Windows Vista SP1 x86
VistaSP2x64                - A Profile for Windows Vista SP2 x64
VistaSP2x86                - A Profile for Windows Vista SP2 x86
Win2003SP0x86              - A Profile for Windows 2003 SP0 x86
Win2003SP1x64              - A Profile for Windows 2003 SP1 x64
Win2003SP1x86              - A Profile for Windows 2003 SP1 x86
Win2003SP2x64              - A Profile for Windows 2003 SP2 x64
Win2003SP2x86              - A Profile for Windows 2003 SP2 x86
Win2008R2SP0x64            - A Profile for Windows 2008 R2 SP0 x64
Win2008R2SP1x64            - A Profile for Windows 2008 R2 SP1 x64
Win2008SP1x64              - A Profile for Windows 2008 SP1 x64
Win2008SP1x86              - A Profile for Windows 2008 SP1 x86
Win2008SP2x64              - A Profile for Windows 2008 SP2 x64
Win2008SP2x86              - A Profile for Windows 2008 SP2 x86
Win2012R2x64               - A Profile for Windows Server 2012 R2 x64
Win2012x64                 - A Profile for Windows Server 2012 x64
Win7SP0x64                 - A Profile for Windows 7 SP0 x64
Win7SP0x86                 - A Profile for Windows 7 SP0 x86
Win7SP1x64                 - A Profile for Windows 7 SP1 x64
Win7SP1x86                 - A Profile for Windows 7 SP1 x86
Win8SP0x64                 - A Profile for Windows 8 x64
Win8SP0x86                 - A Profile for Windows 8 x86
Win8SP1x64                 - A Profile for Windows 8.1 x64
Win8SP1x86                 - A Profile for Windows 8.1 x86
WinXPSP1x64                - A Profile for Windows XP SP1 x64
WinXPSP2x64                - A Profile for Windows XP SP2 x64
WinXPSP2x86                - A Profile for Windows XP SP2 x86
WinXPSP3x86                - A Profile for Windows XP SP3 x86

Address Spaces
--------------
AMD64PagedMemory              - Standard AMD 64-bit address space.
ArmAddressSpace               - No docs        
FileAddressSpace              - This is a direct file AS.
HPAKAddressSpace              - This AS supports the HPAK format
IA32PagedMemory               - Standard IA-32 paging address space.
IA32PagedMemoryPae            - This class implements the IA-32 PAE paging address space. It is responsible
LimeAddressSpace              - Address space for Lime
MachOAddressSpace             - Address space for mach-o files to support atc-ny memory reader
OSXPmemELF                    - This AS supports VirtualBox ELF64 coredump format
QemuCoreDumpElf               - This AS supports Qemu ELF32 and ELF64 coredump format
VMWareAddressSpace            - This AS supports VMware snapshot (VMSS) and saved state (VMSS) files
VMWareMetaAddressSpace        - This AS supports the VMEM format with VMSN/VMSS metadata
VirtualBoxCoreDumpElf64       - This AS supports VirtualBox ELF64 coredump format
WindowsCrashDumpSpace32       - This AS supports windows Crash Dump format
WindowsCrashDumpSpace64       - This AS supports windows Crash Dump format
WindowsCrashDumpSpace64BitMap - This AS supports Windows BitMap Crash Dump format
WindowsHiberFileSpace32       - This is a hibernate address space for windows hibernation files.

Plugins
-------
apihooks                   - Detect API hooks in process and kernel memory
atoms                      - Print session and window station atom tables
atomscan                   - Pool scanner for atom tables
auditpol                   - Prints out the Audit Policies from HKLM\SECURITY\Policy\PolAdtEv
bigpools                   - Dump the big page pools using BigPagePoolScanner
bioskbd                    - Reads the keyboard buffer from Real Mode memory
cachedump                  - Dumps cached domain hashes from memory
callbacks                  - Print system-wide notification routines
clipboard                  - Extract the contents of the windows clipboard
cmdline                    - Display process command-line arguments
cmdscan                    - Extract command history by scanning for _COMMAND_HISTORY
connections                - Print list of open connections [Windows XP and 2003 Only]
connscan                   - Pool scanner for tcp connections
consoles                   - Extract command history by scanning for _CONSOLE_INFORMATION
crashinfo                  - Dump crash-dump information
deskscan                   - Poolscaner for tagDESKTOP (desktops)
devicetree                 - Show device tree
dlldump                    - Dump DLLs from a process address space
dlllist                    - Print list of loaded dlls for each process
driverirp                  - Driver IRP hook detection
driverscan                 - Pool scanner for driver objects
dumpcerts                  - Dump RSA private and public SSL keys
dumpfiles                  - Extract memory mapped and cached files
envars                     - Display process environment variables
eventhooks                 - Print details on windows event hooks
evtlogs                    - Extract Windows Event Logs (XP/2003 only)
filescan                   - Pool scanner for file objects
gahti                      - Dump the USER handle type information
gditimers                  - Print installed GDI timers and callbacks
gdt                        - Display Global Descriptor Table
getservicesids             - Get the names of services in the Registry and return Calculated SID
getsids                    - Print the SIDs owning each process
handles                    - Print list of open handles for each process
hashdump                   - Dumps passwords hashes (LM/NTLM) from memory
hibinfo                    - Dump hibernation file information
hivedump                   - Prints out a hive
hivelist                   - Print list of registry hives.
hivescan                   - Pool scanner for registry hives
hpakextract                - Extract physical memory from an HPAK file
hpakinfo                   - Info on an HPAK file
idt                        - Display Interrupt Descriptor Table
iehistory                  - Reconstruct Internet Explorer cache / history
imagecopy                  - Copies a physical address space out as a raw DD image
imageinfo                  - Identify information for the image
impscan                    - Scan for calls to imported functions
joblinks                   - Print process job link information
kdbgscan                   - Search for and dump potential KDBG values
kpcrscan                   - Search for and dump potential KPCR values
ldrmodules                 - Detect unlinked DLLs
limeinfo                   - Dump Lime file format information
linux_apihooks             - Checks for userland apihooks
linux_arp                  - Print the ARP table
linux_banner               - Prints the Linux banner information
linux_bash                 - Recover bash history from bash process memory
linux_bash_env             - Recover bash's environment variables
linux_bash_hash            - Recover bash hash table from bash process memory
linux_check_afinfo         - Verifies the operation function pointers of network protocols
linux_check_creds          - Checks if any processes are sharing credential structures
linux_check_evt_arm        - Checks the Exception Vector Table to look for syscall table hooking
linux_check_fop            - Check file operation structures for rootkit modifications
linux_check_idt            - Checks if the IDT has been altered
linux_check_inline_kernel  - Check for inline kernel hooks
linux_check_modules        - Compares module list to sysfs info, if available
linux_check_syscall        - Checks if the system call table has been altered
linux_check_syscall_arm    - Checks if the system call table has been altered
linux_check_tty            - Checks tty devices for hooks
linux_cpuinfo              - Prints info about each active processor
linux_dentry_cache         - Gather files from the dentry cache
linux_dmesg                - Gather dmesg buffer
linux_dump_map             - Writes selected memory mappings to disk
linux_elfs                 - Find ELF binaries in process mappings
linux_enumerate_files      - Lists files referenced by the filesystem cache
linux_find_file            - Lists and recovers files from memory
linux_hidden_modules       - Carves memory to find hidden kernel modules
linux_ifconfig             - Gathers active interfaces
linux_info_regs            - It's like 'info registers' in GDB. It prints out all the
linux_iomem                - Provides output similar to /proc/iomem
linux_kernel_opened_files  - Lists files that are opened from within the kernel
linux_keyboard_notifiers   - Parses the keyboard notifier call chain
linux_ldrmodules           - Compares the output of proc maps with the list of libraries from libdl
linux_library_list         - Lists libraries loaded into a process
linux_librarydump          - Dumps shared libraries in process memory to disk
linux_list_raw             - List applications with promiscuous sockets
linux_lsmod                - Gather loaded kernel modules
linux_lsof                 - Lists open files
linux_malfind              - Looks for suspicious process mappings
linux_memmap               - Dumps the memory map for linux tasks
linux_moddump              - Extract loaded kernel modules
linux_mount                - Gather mounted fs/devices
linux_mount_cache          - Gather mounted fs/devices from kmem_cache
linux_netfilter            - Lists Netfilter hooks
linux_netstat              - Lists open sockets
linux_pidhashtable         - Enumerates processes through the PID hash table
linux_pkt_queues           - Writes per-process packet queues out to disk
linux_plthook              - Scan ELF binaries' PLT for hooks to non-NEEDED images
linux_proc_maps            - Gathers process maps for linux
linux_proc_maps_rb         - Gathers process maps for linux through the mappings red-black tree
linux_procdump             - Dumps a process's executable image to disk
linux_process_hollow       - Checks for signs of process hollowing
linux_psaux                - Gathers processes along with full command line and start time
linux_psenv                - Gathers processes along with their environment
linux_pslist               - Gather active tasks by walking the task_struct->task list
linux_pslist_cache         - Gather tasks from the kmem_cache
linux_pstree               - Shows the parent/child relationship between processes
linux_psxview              - Find hidden processes with various process listings
linux_recover_filesystem   - Recovers the entire cached file system from memory
linux_route_cache          - Recovers the routing cache from memory
linux_sk_buff_cache        - Recovers packets from the sk_buff kmem_cache
linux_slabinfo             - Mimics /proc/slabinfo on a running machine
linux_strings              - Match physical offsets to virtual addresses (may take a while, VERY verbose)
linux_threads              - Prints threads of processes
linux_tmpfs                - Recovers tmpfs filesystems from memory
linux_truecrypt_passphrase - Recovers cached Truecrypt passphrases
linux_vma_cache            - Gather VMAs from the vm_area_struct cache
linux_volshell             - Shell in the memory image
linux_yarascan             - A shell in the Linux memory image
lsadump                    - Dump (decrypted) LSA secrets from the registry
mac_adium                  - Lists Adium messages
mac_apihooks               - Checks for API hooks in processes
mac_apihooks_kernel        - Checks to see if system call and kernel functions are hooked
mac_arp                    - Prints the arp table
mac_bash                   - Recover bash history from bash process memory
mac_bash_env               - Recover bash's environment variables
mac_bash_hash              - Recover bash hash table from bash process memory
mac_calendar               - Gets calendar events from Calendar.app
mac_check_mig_table        - Lists entires in the kernel's MIG table
mac_check_syscall_shadow   - Looks for shadow system call tables
mac_check_syscalls         - Checks to see if system call table entries are hooked
mac_check_sysctl           - Checks for unknown sysctl handlers
mac_check_trap_table       - Checks to see if mach trap table entries are hooked
mac_contacts               - Gets contact names from Contacts.app
mac_dead_procs             - Prints terminated/de-allocated processes
mac_dead_sockets           - Prints terminated/de-allocated network sockets
mac_dead_vnodes            - Lists freed vnode structures
mac_dmesg                  - Prints the kernel debug buffer
mac_dump_file              - Dumps a specified file
mac_dump_maps              - Dumps memory ranges of processes
mac_dyld_maps              - Gets memory maps of processes from dyld data structures
mac_find_aslr_shift        - Find the ASLR shift value for 10.8+ images
mac_ifconfig               - Lists network interface information for all devices
mac_ip_filters             - Reports any hooked IP filters
mac_keychaindump           - Recovers possbile keychain keys. Use chainbreaker to open related keychain files
mac_ldrmodules             - Compares the output of proc maps with the list of libraries from libdl
mac_librarydump            - Dumps the executable of a process
mac_list_files             - Lists files in the file cache
mac_list_sessions          - Enumerates sessions
mac_list_zones             - Prints active zones
mac_lsmod                  - Lists loaded kernel modules
mac_lsmod_iokit            - Lists loaded kernel modules through IOkit
mac_lsmod_kext_map         - Lists loaded kernel modules
mac_lsof                   - Lists per-process opened files
mac_machine_info           - Prints machine information about the sample
mac_malfind                - Looks for suspicious process mappings
mac_memdump                - Dump addressable memory pages to a file
mac_moddump                - Writes the specified kernel extension to disk
mac_mount                  - Prints mounted device information
mac_netstat                - Lists active per-process network connections
mac_network_conns          - Lists network connections from kernel network structures
mac_notesapp               - Finds contents of Notes messages
mac_notifiers              - Detects rootkits that add hooks into I/O Kit (e.g. LogKext)
mac_pgrp_hash_table        - Walks the process group hash table
mac_pid_hash_table         - Walks the pid hash table
mac_print_boot_cmdline     - Prints kernel boot arguments
mac_proc_maps              - Gets memory maps of processes
mac_procdump               - Dumps the executable of a process
mac_psaux                  - Prints processes with arguments in user land (**argv)
mac_pslist                 - List Running Processes
mac_pstree                 - Show parent/child relationship of processes
mac_psxview                - Find hidden processes with various process listings
mac_recover_filesystem     - Recover the cached filesystem
mac_route                  - Prints the routing table
mac_socket_filters         - Reports socket filters
mac_strings                - Match physical offsets to virtual addresses (may take a while, VERY verbose)
mac_tasks                  - List Active Tasks
mac_trustedbsd             - Lists malicious trustedbsd policies
mac_version                - Prints the Mac version
mac_volshell               - Shell in the memory image
mac_yarascan               - Scan memory for yara signatures
machoinfo                  - Dump Mach-O file format information
malfind                    - Find hidden and injected code
mbrparser                  - Scans for and parses potential Master Boot Records (MBRs)
memdump                    - Dump the addressable memory for a process
memmap                     - Print the memory map
messagehooks               - List desktop and thread window message hooks
mftparser                  - Scans for and parses potential MFT entries
moddump                    - Dump a kernel driver to an executable file sample
modscan                    - Pool scanner for kernel modules
modules                    - Print list of loaded modules
multiscan                  - Scan for various objects at once
mutantscan                 - Pool scanner for mutex objects
netscan                    - Scan a Vista (or later) image for connections and sockets
notepad                    - List currently displayed notepad text
objtypescan                - Scan for Windows object type objects
patcher                    - Patches memory based on page scans
poolpeek                   - Configurable pool scanner plugin
pooltracker                - Show a summary of pool tag usage
printkey                   - Print a registry key, and its subkeys and values
privs                      - Display process privileges
procdump                   - Dump a process to an executable file sample
pslist                     - Print all running processes by following the EPROCESS lists
psscan                     - Pool scanner for process objects
pstree                     - Print process list as a tree
psxview                    - Find hidden processes with various process listings
raw2dmp                    - Converts a physical memory sample to a windbg crash dump
screenshot                 - Save a pseudo-screenshot based on GDI windows
sessions                   - List details on _MM_SESSION_SPACE (user logon sessions)
shellbags                  - Prints ShellBags info
shimcache                  - Parses the Application Compatibility Shim Cache registry key
sockets                    - Print list of open sockets
sockscan                   - Pool scanner for tcp socket objects
ssdt                       - Display SSDT entries
strings                    - Match physical offsets to virtual addresses (may take a while, VERY verbose)
svcscan                    - Scan for Windows services
symlinkscan                - Pool scanner for symlink objects
thrdscan                   - Pool scanner for thread objects
threads                    - Investigate _ETHREAD and _KTHREADs
timeliner                  - Creates a timeline from various artifacts in memory
timers                     - Print kernel timers and associated module DPCs
truecryptmaster            - Recover TrueCrypt 7.1a Master Keys
truecryptpassphrase        - TrueCrypt Cached Passphrase Finder
truecryptsummary           - TrueCrypt Summary
unloadedmodules            - Print list of unloaded modules
userassist                 - Print userassist registry keys and information
userhandles                - Dump the USER handle tables
vaddump                    - Dumps out the vad sections to a file
vadinfo                    - Dump the VAD info
vadtree                    - Walk the VAD tree and display in tree format
vadwalk                    - Walk the VAD tree
vboxinfo                   - Dump virtualbox information
verinfo                    - Prints out the version information from PE images
vmwareinfo                 - Dump VMware VMSS/VMSN information
volshell                   - Shell in the memory image
windows                    - Print Desktop Windows (verbose details)
wintree                    - Print Z-Order Desktop Windows Tree
wndscan                    - Pool scanner for window stations
yarascan                   - Scan process or kernel memory with Yara signatures

3. To get more information on a Windows memory sample and to make sure Volatility
   supports that sample type, run 'python vol.py imageinfo -f <imagename>' or 'python vol.py kdbgscan -f <imagename>'

   Example:
   
    $ python vol.py imageinfo -f WIN-II7VOJTUNGL-20120324-193051.raw 
    Volatility Foundation Volatility Framework 2.4
    Determining profile based on KDBG search...
    
              Suggested Profile(s) : Win2008R2SP0x64, Win7SP1x64, Win7SP0x64, Win2008R2SP1x64 (Instantiated with Win7SP0x64)
                         AS Layer1 : AMD64PagedMemory (Kernel AS)
                         AS Layer2 : FileAddressSpace (/Path/to/WIN-II7VOJTUNGL-20120324-193051.raw)
                          PAE type : PAE
                               DTB : 0x187000L
                              KDBG : 0xf800016460a0
              Number of Processors : 1
         Image Type (Service Pack) : 1
                    KPCR for CPU 0 : 0xfffff80001647d00L
                 KUSER_SHARED_DATA : 0xfffff78000000000L
               Image date and time : 2012-03-24 19:30:53 UTC+0000
         Image local date and time : 2012-03-25 03:30:53 +0800

4. Run some other plugins. -f is a required option for all plugins. Some
   also require/accept other options. Run "python vol.py <plugin> -h" for
   more information on a particular command.  A Command Reference wiki
   is also available on the Google Code site:

        https://github.com/volatilityfoundation/volatility/wiki/Command-Reference23

   as well as Basic Usage:

        https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage23

Licensing and Copyright
=======================

Copyright (C) 2007-2014 Volatility Foundation

All Rights Reserved

Volatility is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Volatility is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Volatility.  If not, see <http://www.gnu.org/licenses/>.

Bugs and Support
================
There is no support provided with Volatility. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. 

If you think you've found a bug, please report it at:

    https://github.com/volatilityfoundation/volatility/issues

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
    https://github.com/volatilityfoundation/volatility/wiki

Missing or Truncated Information
================================
Volatility Foundation makes no claims about the validity or correctness of the
output of Volatility. Many factors may contribute to the
incorrectness of output from Volatility including, but not
limited to, malicious modifications to the operating system,
incomplete information due to swapping, and information corruption on
image acquisition. 

Command Reference 
====================
The following url contains a reference of all commands supported by 
Volatility.

    https://github.com/volatilityfoundation/volatility/wiki/Command-Reference23


