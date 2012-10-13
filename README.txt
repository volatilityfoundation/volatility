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

Volatility does not provide memory sample acquisition
capabilities. For acquisition, there are both free and commercial
solutions available. If you would like suggestions about suitable 
acquisition solutions, please contact us at:

volatility (at) volatilesystems (dot) com

Volatility currently provides the following extraction capabilities for 
memory samples:

Windows Basic
    Current date, time, CPU count, CPU speed, service pack
    Current thread and idle thread
    Addresses of the KDBG, KPCR, DTB, PsActiveProcessHead, PsLoadedModuleList, etc
Processes
    List active processes (column or tree view)
    Scan for hidden or terminated _EPROCESS objects (using pool tags or _DISPATCHER_HEADER)
    Enumerate DLLs in the PEB LDR lists
    Rebuild/extract DLLs or EXEs to disk based on name, base address, or physical offset
    Print open handles to files, registry keys, mutexes, threads, processes, etc
    List security identifiers (SIDs) for processes
    Scan for cmd.exe command history and full console input/output buffers
    List process environment variables
    Print PE version information from processes or DLLs (file version, company name, etc)
    Enumerate imported and exported API functions anywhere in process or kernel memory
    Show a list of virtual and physical mappings of all pages available to a process
    Dump process address space to disk as a single file
    Analyze Virtual Address Descriptor (VAD) nodes, show page protection, flags, and mapped files
    Represent the VAD in tree form or Graphviz .dot graphs
    Dump each VAD range to disk for inspecting with external tools
    Parse XP/2003 event log records
Kernel Memory
    List loaded kernel modules and scan for hidden/unloaded module structures
    Extract PE files including drivers from anywhere in kernel memory
    Dump the SSDT for all 32- and 64-bit windows systems
    Scan for driver objects, print IRP major function tables
    Show devices and device tree layout
    Scan for file objects (can show deleted files, closed handles, etc)
    Scan for threads, mutex objects and symbolic links
GUI Memory
    Analyze logon sessions and the processes and mapped images belonging to the session
    Scan for window stations and clipboard artifacts (clipboard snooping malware)
    Scan for desktops, analyze desktop heaps and attached GUI threads
    Locate and parse atom tables (class names, DLL injection paths, etc)
    Extract the contents of the windows clipboard
    Analyze message hooks and event hooks, show the injected DLL and function address
    Dump all USER object types, pool tags, and flags from the gahti
    Print all open USER handles, associated threads or processes, and object offsets
    Display details on all windows, such as coordiates, window title, class, procedure address, etc
    Take screen shots from memory dumps (requires PIL)
Malware Analysis
    Find injected code and DLLs, unpacker stubs, and decrypted configurations, etc
    Scan process or kernel memory for any string, regular expression, byte pattern, URL, etc
    Analyze services, their status (running, stopped, etc) and associated process or driver
    Cross-reference memory mapped executable files with PEB lists to find injected code
    Scan for imported functions in process or kernel memory (without using import tables)
    Detect API hooks (Inline, IAT, EAT), hooked winsock tables, syscall hooks, etc
    Analyze the IDT and GDT for each CPU, alert on hooks and disassemble code
    Dump details of threads, such as hardware breakpoints, context registers, etc
    Enumerate kernel callbacks for process creation, thread creation, and image loading
    Display FS registration, registry, shutdown, bugcheck, and debug print callbacks
    Detect hidden processes with alternate process listings (6+ sources)
    Analyze kernel timers and their DPC routine functions
Networking
    Walk the list of connection and socket objects for XP/2003 systems
    Scan physical memory for network information (recover closed/terminated artifacts)
    Determine if listening sockets are IPv4, IPv6, etc and link to their owning processes
Registry
    Scan for registry hives in memory
    Parse and print any value or key cached in kernel memory, with timestamps
    Dump an entire registry hive recursively
    Extract cached domain credentials from the registry
    Locate and decrypt NT/NTLM hashes and LSA secrets
    Analyze user assist keys, the shimcache, and shellbags
    Crash Dumps, Hibernation, Conversion
    Print crash dump and hibernation file header information
    Run any plugin on a crash dump or hibernation file (hiberfil.sys)
    Convert a raw memory dump to a crash dump for opening in !WinDBG
    Convert a crash dump or hibernation file to a raw memory dump
Miscellaneous
    Link strings found at physical offsets to their owning kernel address or process
    Interactive shell with disassembly, type display, hexdumps, etc

Volatility also supports a variety of sample file formats and the
ability to convert between these formats:

  - Raw linear sample (dd)
  - Hibernation file
  - Crash dump file

For a more detailed list of capabilities, see the following:

    http://code.google.com/p/volatility/wiki/FeaturesByPlugin23
    http://code.google.com/p/volatility/wiki/CommandReference23

Example Data
============

If you want to give Volatility a try, you can download exemplar
data hosted by NIST at the following url:

    http://www.cfreds.nist.gov/mem/memory-images.rar

Links to other public memory images can be found at the following url:

    http://code.google.com/p/volatility/wiki/PublicMemoryImages

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

Requirements
============
- Python 2.6 or later, but not 3.0. http://www.python.org

Some plugins may have other requirements which can be found at: 
    http://code.google.com/p/volatility/wiki/Release23

Quick Start
===========
1. Unpack the latest version of Volatility from
   https://www.volatilesystems.com/default/volatility or 
   http://code.google.com/p/volatility/downloads/list
   
2. To see available options, run "python vol.py -h"  

   Example:

> python vol.py -h 
Volatile Systems Volatility Framework 2.1_rc3
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=/Users/Michael/.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --plugins=PLUGINS     Additional plugin directories to use (colon separated)
  --info                Print information about all registered objects
  --cache-directory=/Users/Michael/.cache/volatility
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
  --use-old-as          Use the legacy address spaces
  --output=text         Output in this format (format support is module
                        specific)
  --output-file=OUTPUT_FILE
                        write output in this file
  -v, --verbose         Verbose information
  -k KPCR, --kpcr=KPCR  Specify a specific KPCR address
  -g KDBG, --kdbg=KDBG  Specify a specific KDBG virtual address

	Supported Plugin Commands:

		apihooks       	Detect API hooks in process and kernel memory
		bioskbd        	Reads the keyboard buffer from Real Mode memory
		callbacks      	Print system-wide notification routines
		cmdscan        	Extract command history by scanning for _COMMAND_HISTORY
		connections    	Print list of open connections [Windows XP and 2003 Only]
		connscan       	Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
		consoles       	Extract command history by scanning for _CONSOLE_INFORMATION
		crashinfo      	Dump crash-dump information
		devicetree     	Show device tree
		dlldump        	Dump DLLs from a process address space
		dlllist        	Print list of loaded dlls for each process
		driverirp      	Driver IRP hook detection
		driverscan     	Scan for driver objects _DRIVER_OBJECT 
		envars         	Display process environment variables
		filescan       	Scan Physical memory for _FILE_OBJECT pool allocations
		gdt            	Display Global Descriptor Table
		getsids        	Print the SIDs owning each process
		handles        	Print list of open handles for each process
		hashdump       	Dumps passwords hashes (LM/NTLM) from memory
		hibinfo        	Dump hibernation file information
		hivedump       	Prints out a hive
		hivelist       	Print list of registry hives.
		hivescan       	Scan Physical memory for _CMHIVE objects (registry hives)
		idt            	Display Interrupt Descriptor Table
		imagecopy      	Copies a physical address space out as a raw DD image
		imageinfo      	Identify information for the image 
		impscan        	Scan for calls to imported functions
		kdbgscan       	Search for and dump potential KDBG values
		kpcrscan       	Search for and dump potential KPCR values
		ldrmodules     	Detect unlinked DLLs
		lsadump        	Dump (decrypted) LSA secrets from the registry
		malfind        	Find hidden and injected code
		memdump        	Dump the addressable memory for a process
		memmap         	Print the memory map
		moddump        	Dump a kernel driver to an executable file sample
		modscan        	Scan Physical memory for _LDR_DATA_TABLE_ENTRY objects
		modules        	Print list of loaded modules
		mutantscan     	Scan for mutant objects _KMUTANT 
		patcher        	Patches memory based on page scans
		printkey       	Print a registry key, and its subkeys and values
		procexedump    	Dump a process to an executable file sample
		procmemdump    	Dump a process to an executable memory sample
		pslist         	print all running processes by following the EPROCESS lists 
		psscan         	Scan Physical memory for _EPROCESS pool allocations
		pstree         	Print process list as a tree
		psxview        	Find hidden processes with various process listings
		raw2dmp        	Converts a physical memory sample to a windbg crash dump
		shimcache      	Parses the Application Compatibility Shim Cache registry key
		sockets        	Print list of open sockets
		sockscan       	Scan Physical memory for _ADDRESS_OBJECT objects (tcp sockets)
		ssdt           	Display SSDT entries
		strings        	Match physical offsets to virtual addresses (may take a while, VERY verbose)
		svcscan        	Scan for Windows services
		symlinkscan    	Scan for symbolic link objects 
		thrdscan       	Scan physical memory for _ETHREAD objects
		threads        	Investigate _ETHREAD and _KTHREADs
		timers         	Print kernel timers and associated module DPCs
		userassist     	Print userassist registry keys and information
		vaddump        	Dumps out the vad sections to a file
		vadinfo        	Dump the VAD info
		vadtree        	Walk the VAD tree and display in tree format
		vadwalk        	Walk the VAD tree
		volshell       	Shell in the memory image
		yarascan       	Scan process or kernel memory with Yara signatures

3. To get more information on a sample and to make sure Volatility
   supports that sample type, run 'python vol.py imageinfo -f <imagename>'

   Example:
   
    > python vol.py imageinfo -f WIN-II7VOJTUNGL-20120324-193051.raw 
    Volatile Systems Volatility Framework 2.1_rc3
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


